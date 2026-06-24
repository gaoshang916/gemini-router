package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultGeminiEndpoint = "https://generativelanguage.googleapis.com"

type Config struct {
	ProjectAPIKey   string      `json:"project_api_key"`
	ProjectProxy    string      `json:"project_proxy"`
	AutoRetry       int         `json:"auto_retry"`
	LogRetentionDay int         `json:"log_retention_day"`
	GeminiKeys      []GeminiKey `json:"gemini_keys"`
}

type GeminiKey struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Remark    string `json:"remark,omitempty"`
	Key       string `json:"key"`
	Proxy     string `json:"proxy"`
	LastOK    *bool  `json:"last_ok,omitempty"`
	LastTest  string `json:"last_test,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

type RequestLog struct {
	Time       string `json:"time"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	ClientIP   string `json:"client_ip"`
	StatusCode int    `json:"status_code"`
	KeyName    string `json:"key_name,omitempty"`
	Attempts   int    `json:"attempts"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

type RequestLogStore struct {
	mu   sync.Mutex
	path string
}

func NewRequestLogStore(path string) *RequestLogStore {
	return &RequestLogStore{path: path}
}

func (s *RequestLogStore) Append(entry RequestLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

func (s *RequestLogStore) Recent(limit int) ([]RequestLog, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	if len(lines) == 1 && len(lines[0]) == 0 {
		return nil, nil
	}
	start := 0
	if limit > 0 && len(lines) > limit {
		start = len(lines) - limit
	}
	logs := make([]RequestLog, 0, len(lines)-start)
	for i := len(lines) - 1; i >= start; i-- {
		var entry RequestLog
		if err := json.Unmarshal(lines[i], &entry); err != nil {
			return nil, err
		}
		logs = append(logs, entry)
	}
	return logs, nil
}

func (s *RequestLogStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, nil, 0o600)
}

func (s *RequestLogStore) Cleanup(retentionDays int, now time.Time) error {
	retentionDays = clampLogRetentionDay(retentionDays)
	if retentionDays == 0 {
		return nil
	}
	cutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var kept [][]byte
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry RequestLog
		if err := json.Unmarshal(line, &entry); err != nil {
			kept = append(kept, line)
			continue
		}
		t, err := time.Parse(time.RFC3339, entry.Time)
		if err != nil || !t.Before(cutoff) {
			kept = append(kept, line)
		}
	}
	out := bytes.Join(kept, []byte("\n"))
	if len(out) > 0 {
		out = append(out, '\n')
	}
	return os.WriteFile(s.path, out, 0o600)
}

const adminSessionCookie = "gemini_router_admin_key"

type Store struct {
	mu     sync.RWMutex
	path   string
	config Config
	nextID int
	rr     int
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path, config: Config{GeminiKeys: []GeminiKey{}}, nextID: 1}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, &s.config); err != nil {
		return err
	}
	maxID := 0
	for _, k := range s.config.GeminiKeys {
		if k.ID > maxID {
			maxID = k.ID
		}
	}
	s.nextID = maxID + 1
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

func (s *Store) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.config
	cfg.GeminiKeys = append([]GeminiKey(nil), s.config.GeminiKeys...)
	return cfg
}

func (s *Store) UpdateProject(apiKey, projectProxy string, autoRetry int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.ProjectAPIKey = strings.TrimSpace(apiKey)
	s.config.ProjectProxy = strings.TrimSpace(projectProxy)
	s.config.AutoRetry = clampAutoRetry(autoRetry)
	return s.saveLocked()
}

func (s *Store) UpdateLogRetention(days int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.LogRetentionDay = clampLogRetentionDay(days)
	return s.saveLocked()
}

func (s *Store) AddKeys(lines []string, proxyURL, remark string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range lines {
		key := strings.TrimSpace(line)
		if key == "" {
			continue
		}
		s.config.GeminiKeys = append(s.config.GeminiKeys, GeminiKey{ID: s.nextID, Name: fmt.Sprintf("key-%d", s.nextID), Remark: strings.TrimSpace(remark), Key: key, Proxy: strings.TrimSpace(proxyURL)})
		s.nextID++
	}
	return s.saveLocked()
}

func (s *Store) DeleteKey(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := s.config.GeminiKeys[:0]
	for _, k := range s.config.GeminiKeys {
		if k.ID != id {
			keys = append(keys, k)
		}
	}
	s.config.GeminiKeys = keys
	return s.saveLocked()
}

func (s *Store) UpdateKey(id int, name, proxyURL, remark string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.config.GeminiKeys {
		if s.config.GeminiKeys[i].ID == id {
			s.config.GeminiKeys[i].Name = strings.TrimSpace(name)
			s.config.GeminiKeys[i].Proxy = strings.TrimSpace(proxyURL)
			s.config.GeminiKeys[i].Remark = strings.TrimSpace(remark)
			break
		}
	}
	return s.saveLocked()
}

func (s *Store) SetTestResult(id int, ok bool, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Format(time.RFC3339)
	for i := range s.config.GeminiKeys {
		if s.config.GeminiKeys[i].ID == id {
			s.config.GeminiKeys[i].LastOK = &ok
			s.config.GeminiKeys[i].LastTest = now
			if ok {
				s.config.GeminiKeys[i].LastError = ""
			} else {
				s.config.GeminiKeys[i].LastError = msg
			}
			break
		}
	}
	return s.saveLocked()
}

func (s *Store) NextKey() (GeminiKey, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.config.GeminiKeys) == 0 {
		return GeminiKey{}, s.config.ProjectProxy, false
	}
	for i := 0; i < len(s.config.GeminiKeys); i++ {
		idx := (s.rr + i) % len(s.config.GeminiKeys)
		k := s.config.GeminiKeys[idx]
		if k.LastOK == nil || *k.LastOK {
			s.rr = idx + 1
			proxyURL := k.Proxy
			if proxyURL == "" {
				proxyURL = s.config.ProjectProxy
			}
			return k, proxyURL, true
		}
	}
	k := s.config.GeminiKeys[s.rr%len(s.config.GeminiKeys)]
	s.rr++
	proxyURL := k.Proxy
	if proxyURL == "" {
		proxyURL = s.config.ProjectProxy
	}
	return k, proxyURL, true
}

type App struct {
	store          *Store
	logStore       *RequestLogStore
	geminiEndpoint string
	adminTemplate  *template.Template
	requestTimeout time.Duration
	cleanupStop    chan struct{}
}

func main() {
	dataPath := getenv("DATA_PATH", "./data/config.json")
	logPath := getenv("LOG_PATH", filepath.Join(filepath.Dir(dataPath), "request_logs.jsonl"))
	store, err := NewStore(dataPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	logStore := NewRequestLogStore(logPath)
	app := &App{
		store:          store,
		logStore:       logStore,
		geminiEndpoint: strings.TrimRight(getenv("GEMINI_ENDPOINT", defaultGeminiEndpoint), "/"),
		adminTemplate:  template.Must(template.New("admin").Funcs(template.FuncMap{"mask": mask, "testStatus": testStatus}).Parse(adminHTML)),
		requestTimeout: 120 * time.Second,
	}
	addr := getenv("ADDR", ":8080")
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleAdmin)
	mux.HandleFunc("/admin", app.handleAdmin)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/admin/", app.handleAdminAction)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/v1/", app.handleProxy)
	mux.HandleFunc("/v1beta/", app.handleProxy)
	app.startLogCleanup()
	log.Printf("gemini-router listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Snapshot()
	if cfg.ProjectAPIKey == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := struct{ Msg string }{Msg: r.URL.Query().Get("msg")}
		if err := template.Must(template.New("login").Parse(loginHTML)).Execute(w, data); err != nil {
			log.Printf("render login: %v", err)
		}
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !constantTimeEqual(r.FormValue("project_api_key"), cfg.ProjectAPIKey) {
		http.Redirect(w, r, "/login?msg=invalid", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    adminSessionValue(cfg.ProjectAPIKey),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	if !a.authorizeAdmin(w, r) {
		return
	}
	cfg := a.store.Snapshot()
	logs, logErr := a.recentRequestLogs(200)
	msg := r.URL.Query().Get("msg")
	if logErr != nil {
		msg = "读取请求日志失败: " + logErr.Error()
	}
	data := struct {
		Config Config
		Logs   []RequestLog
		Msg    string
	}{Config: cfg, Logs: logs, Msg: msg}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.adminTemplate.Execute(w, data); err != nil {
		log.Printf("render admin: %v", err)
	}
}

func (a *App) handleAdminAction(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Handle both multipart/form-data (AJAX fetch with FormData) and URL-encoded forms
	if err := r.ParseMultipartForm(32 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var err error
	switch r.URL.Path {
	case "/admin/project":
		autoRetry, _ := strconv.Atoi(r.FormValue("auto_retry"))
		err = a.store.UpdateProject(r.FormValue("project_api_key"), r.FormValue("project_proxy"), autoRetry)
	case "/admin/logs/retention":
		days, _ := strconv.Atoi(r.FormValue("log_retention_day"))
		err = a.store.UpdateLogRetention(days)
	case "/admin/logs/clear":
		err = a.clearRequestLogs()
	case "/admin/keys/add":
		err = a.store.AddKeys(strings.Split(r.FormValue("keys"), "\n"), r.FormValue("proxy"), r.FormValue("remark"))
	case "/admin/keys/delete":
		id, _ := strconv.Atoi(r.FormValue("id"))
		err = a.store.DeleteKey(id)
	case "/admin/keys/update":
		id, _ := strconv.Atoi(r.FormValue("id"))
		err = a.store.UpdateKey(id, r.FormValue("name"), r.FormValue("proxy"), r.FormValue("remark"))
	case "/admin/keys/test":
		id, _ := strconv.Atoi(r.FormValue("id"))
		err = a.testAndStoreKey(r.Context(), id)
	case "/admin/keys/test-all":
		err = a.testAllKeys(r.Context())
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		if wantsJSON(r) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": err.Error()})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "操作已完成"})
		return
	}
	http.Redirect(w, r, "/admin?msg=saved", http.StatusSeeOther)
}

func wantsJSON(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("X-Requested-With"), "fetch") || strings.Contains(r.Header.Get("Accept"), "application/json")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func (a *App) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	logEntry := RequestLog{
		Time:     start.Format(time.RFC3339),
		Method:   r.Method,
		Path:     sanitizedRequestURI(r),
		ClientIP: clientIP(r),
	}
	defer func() {
		logEntry.DurationMS = time.Since(start).Milliseconds()
		a.appendRequestLog(logEntry)
	}()
	if !a.authorizeProxy(w, r) {
		logEntry.StatusCode = http.StatusUnauthorized
		logEntry.Error = "unauthorized"
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logEntry.StatusCode = http.StatusBadRequest
		logEntry.Error = err.Error()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := a.store.Snapshot()
	maxAttempts := clampAutoRetry(cfg.AutoRetry) + 1
	if len(cfg.GeminiKeys) > 0 && maxAttempts > len(cfg.GeminiKeys) {
		maxAttempts = len(cfg.GeminiKeys)
	}

	var lastErr error
	var lastStatus int
	var tried []string
	for attempt := 0; attempt < maxAttempts; attempt++ {
		key, proxyURL, ok := a.store.NextKey()
		if !ok {
			logEntry.StatusCode = http.StatusServiceUnavailable
			logEntry.Error = "no gemini api key configured"
			http.Error(w, "no gemini api key configured", http.StatusServiceUnavailable)
			return
		}
		tried = append(tried, key.Name)
		logEntry.KeyName = key.Name
		logEntry.Attempts = attempt + 1
		resp, err := a.forwardProxyRequest(r, body, key, proxyURL)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= http.StatusBadRequest && attempt+1 < maxAttempts {
			lastStatus = resp.StatusCode
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			continue
		}
		defer resp.Body.Close()
		copyHeaders(w.Header(), resp.Header)
		removeHopByHopHeaders(w.Header())
		w.Header().Set("X-Gemini-Router-Key", key.Name)
		w.Header().Set("X-Gemini-Router-Attempts", strconv.Itoa(attempt+1))
		w.Header().Set("X-Gemini-Router-Tried-Keys", strings.Join(tried, ","))
		w.WriteHeader(resp.StatusCode)
		logEntry.StatusCode = resp.StatusCode
		_, _ = io.Copy(w, resp.Body)
		return
	}
	if lastErr != nil {
		logEntry.StatusCode = http.StatusBadGateway
		logEntry.Error = lastErr.Error()
		http.Error(w, lastErr.Error(), http.StatusBadGateway)
		return
	}
	logEntry.StatusCode = http.StatusBadGateway
	logEntry.Error = fmt.Sprintf("gemini api request failed after retries; last status: %d", lastStatus)
	http.Error(w, fmt.Sprintf("gemini api request failed after retries; last status: %d", lastStatus), http.StatusBadGateway)
}

func (a *App) appendRequestLog(entry RequestLog) {
	if a.logStore == nil {
		return
	}
	if err := a.logStore.Append(entry); err != nil {
		log.Printf("append request log: %v", err)
	}
}

func (a *App) recentRequestLogs(limit int) ([]RequestLog, error) {
	if a.logStore == nil {
		return nil, nil
	}
	return a.logStore.Recent(limit)
}

func (a *App) clearRequestLogs() error {
	if a.logStore == nil {
		return nil
	}
	return a.logStore.Clear()
}

func (a *App) startLogCleanup() {
	a.cleanupStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		a.runLogCleanup()
		for {
			select {
			case <-ticker.C:
				a.runLogCleanup()
			case <-a.cleanupStop:
				return
			}
		}
	}()
}

func (a *App) runLogCleanup() {
	if a.logStore == nil {
		return
	}
	if err := a.logStore.Cleanup(a.store.Snapshot().LogRetentionDay, time.Now()); err != nil {
		log.Printf("cleanup request logs: %v", err)
	}
}

func (a *App) forwardProxyRequest(r *http.Request, body []byte, key GeminiKey, proxyURL string) (*http.Response, error) {
	target, err := url.Parse(a.geminiEndpoint + r.URL.Path)
	if err != nil {
		return nil, err
	}
	target.RawQuery = r.URL.Query().Encode()
	q := target.Query()
	q.Set("key", key.Key)
	target.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(r.Context(), a.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	copyHeaders(req.Header, r.Header)
	removeHopByHopHeaders(req.Header)
	req.Header.Del("Host")
	req.Header.Del("Authorization")
	req.Header.Del("X-API-Key")
	req.Header.Del("x-goog-api-key")
	req.Host = target.Host

	client, err := httpClient(proxyURL, a.requestTimeout)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func clampAutoRetry(n int) int {
	if n < 0 {
		return 0
	}
	if n > 5 {
		return 5
	}
	return n
}

func clampLogRetentionDay(n int) int {
	if n < 0 {
		return 0
	}
	if n > 365 {
		return 365
	}
	return n
}

func sanitizedRequestURI(r *http.Request) string {
	u := *r.URL
	q := u.Query()
	for _, name := range []string{"key", "api_key", "x-goog-api-key", "access_token"} {
		if q.Has(name) {
			q.Set(name, "REDACTED")
		}
	}
	u.RawQuery = q.Encode()
	return u.RequestURI()
}

func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		if first := strings.TrimSpace(strings.Split(forwarded, ",")[0]); first != "" {
			return first
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func adminSessionValue(projectAPIKey string) string {
	mac := hmac.New(sha256.New, []byte(projectAPIKey))
	_, _ = mac.Write([]byte("gemini-router-admin-session"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func projectAPIKeyFromRequest(r *http.Request) string {
	if got := r.Header.Get("X-API-Key"); got != "" {
		return got
	}
	if got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); got != "" {
		return got
	}
	return r.Header.Get("x-goog-api-key")
}

func (a *App) authorizeProxy(w http.ResponseWriter, r *http.Request) bool {
	cfg := a.store.Snapshot()
	if cfg.ProjectAPIKey == "" {
		return true
	}
	if !constantTimeEqual(projectAPIKeyFromRequest(r), cfg.ProjectAPIKey) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *App) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	cfg := a.store.Snapshot()
	if cfg.ProjectAPIKey == "" {
		return true
	}
	if cookie, err := r.Cookie(adminSessionCookie); err == nil && constantTimeEqual(cookie.Value, adminSessionValue(cfg.ProjectAPIKey)) {
		return true
	}
	if constantTimeEqual(r.Header.Get("X-API-Key"), cfg.ProjectAPIKey) {
		return true
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	return false
}

func (a *App) testAndStoreKey(ctx context.Context, id int) error {
	cfg := a.store.Snapshot()
	for _, k := range cfg.GeminiKeys {
		if k.ID == id {
			proxyURL := k.Proxy
			if proxyURL == "" {
				proxyURL = cfg.ProjectProxy
			}
			ok, msg := a.testKey(ctx, k.Key, proxyURL)
			return a.store.SetTestResult(id, ok, msg)
		}
	}
	return fmt.Errorf("key id %d not found", id)
}

func (a *App) testAllKeys(ctx context.Context) error {
	cfg := a.store.Snapshot()
	for _, k := range cfg.GeminiKeys {
		proxyURL := k.Proxy
		if proxyURL == "" {
			proxyURL = cfg.ProjectProxy
		}
		ok, msg := a.testKey(ctx, k.Key, proxyURL)
		if err := a.store.SetTestResult(k.ID, ok, msg); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) testKey(ctx context.Context, apiKey, proxyURL string) (bool, string) {
	client, err := httpClient(proxyURL, 20*time.Second)
	if err != nil {
		return false, err.Error()
	}
	target := fmt.Sprintf("%s/v1beta/models?key=%s", a.geminiEndpoint, url.QueryEscape(apiKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, err.Error()
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, "ok"
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return false, fmt.Sprintf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
}

func httpClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.TrimSpace(proxyURL) != "" {
		u, err := parseSocks5URL(proxyURL)
		if err != nil {
			return nil, err
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, fmt.Errorf("unsupported network %q", network)
			}
			return dialSocks5(ctx, u, addr)
		}
	}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

func parseSocks5URL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("only socks5 proxy is supported, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing socks5 proxy host")
	}
	return u, nil
}

func dialSocks5(ctx context.Context, proxyURL *url.URL, target string) (net.Conn, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := socks5Handshake(conn, proxyURL, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5Handshake(conn net.Conn, proxyURL *url.URL, target string) error {
	methods := []byte{0x00}
	username := ""
	password := ""
	if proxyURL.User != nil {
		username = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
		methods = append(methods, 0x02)
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("invalid socks5 version %d", buf[0])
	}
	if buf[1] == 0xff {
		return fmt.Errorf("socks5 proxy rejected authentication methods")
	}
	if buf[1] == 0x02 {
		if len(username) > 255 || len(password) > 255 {
			return fmt.Errorf("socks5 username/password is too long")
		}
		auth := []byte{0x01, byte(len(username))}
		auth = append(auth, []byte(username)...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, []byte(password)...)
		if _, err := conn.Write(auth); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		if buf[1] != 0x00 {
			return fmt.Errorf("socks5 username/password authentication failed")
		}
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid target port %q", portText)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("target host is too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("invalid socks5 response version %d", buf[0])
	}
	if buf[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed with code 0x%02x", buf[1])
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	var skip int
	switch head[1] {
	case 0x01:
		skip = net.IPv4len + 2
	case 0x04:
		skip = net.IPv6len + 2
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		skip = int(lenBuf[0]) + 2
	default:
		return fmt.Errorf("unknown socks5 address type 0x%02x", head[1])
	}
	_, err = io.CopyN(io.Discard, conn, int64(skip))
	return err
}

func copyHeaders(dst, src http.Header) {
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func removeHopByHopHeaders(h http.Header) {
	for _, header := range h.Values("Connection") {
		for _, name := range strings.Split(header, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(name)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func testStatus(k GeminiKey) template.HTML {
	if k.LastOK == nil {
		return template.HTML("未测试")
	}
	if *k.LastOK {
		return template.HTML(`✅<br><span class="muted">` + template.HTMLEscapeString(k.LastTest) + `</span>`)
	}
	return template.HTML(`❌ ` + template.HTMLEscapeString(k.LastError) + `<br><span class="muted">` + template.HTMLEscapeString(k.LastTest) + `</span>`)
}

func mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

const adminHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gemini Router 管理</title>
  <style>
    :root { color-scheme: light; --bg: #eef2ff; --card: #ffffff; --text: #111827; --muted: #6b7280; --line: #e5e7eb; --primary: #2563eb; --primary-dark: #1d4ed8; --danger: #dc2626; --success: #16a34a; --shadow: 0 18px 45px #1e293b14; }
    * { box-sizing: border-box; }
    body { font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; min-height: 100vh; background: radial-gradient(circle at top left, #dbeafe 0, transparent 30rem), linear-gradient(135deg, #f8fafc 0%, var(--bg) 100%); color: var(--text); }
    main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 2rem 0 3rem; }
    .hero { display: flex; justify-content: space-between; align-items: center; gap: 1rem; margin-bottom: 1.25rem; padding: 1.5rem; background: #ffffffcc; border: 1px solid #fff; border-radius: 24px; box-shadow: var(--shadow); backdrop-filter: blur(10px); }
    .hero h1 { margin: 0; font-size: clamp(1.8rem, 3vw, 2.6rem); letter-spacing: -.04em; }
    .hero p { margin: .35rem 0 0; color: var(--muted); }
    .logout { color: var(--primary); font-weight: 700; text-decoration: none; }
    .grid { display: grid; grid-template-columns: minmax(0, 1fr); gap: 1rem; }
    .two-col { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    section { background: var(--card); border: 1px solid #e0e7ff; border-radius: 18px; padding: 1.25rem; box-shadow: var(--shadow); }
    h2 { margin: 0 0 .35rem; font-size: 1.15rem; }
    label { display: block; margin: .85rem 0 .3rem; font-weight: 700; font-size: .92rem; }
    input, textarea { width: 100%; padding: .72rem .78rem; border: 1px solid #cbd5e1; border-radius: 10px; background: #fff; transition: border-color .15s, box-shadow .15s; }
    input:focus, textarea:focus { outline: 0; border-color: var(--primary); box-shadow: 0 0 0 4px #2563eb22; }
    textarea { min-height: 8rem; resize: vertical; }
    button { display: inline-flex; align-items: center; justify-content: center; gap: .35rem; background: var(--primary); color: white; border: 0; padding: .62rem .95rem; border-radius: 10px; cursor: pointer; margin-top: .75rem; font-weight: 700; transition: transform .12s, background .12s, opacity .12s; }
    button:hover { background: var(--primary-dark); transform: translateY(-1px); }
    button:disabled { opacity: .65; cursor: wait; transform: none; }
    button.secondary { background: #475569; }
    button.danger { background: var(--danger); }
    .table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 14px; margin-top: .85rem; }
    table { width: 100%; border-collapse: collapse; min-width: 760px; }
    th { background: #f8fafc; color: #475569; font-size: .82rem; text-transform: uppercase; letter-spacing: .04em; }
    th, td { border-bottom: 1px solid var(--line); padding: .72rem; text-align: left; vertical-align: top; }
    tbody tr:hover { background: #f8fafc; }
    tbody tr:last-child td { border-bottom: 0; }
    code { background: #f1f5f9; color: #0f172a; padding: .18rem .38rem; border-radius: 6px; white-space: nowrap; }
    .msg { color: var(--success); font-weight: 700; }
    .muted { color: var(--muted); font-size: .92rem; }
    .row-actions { display: flex; gap: .45rem; flex-wrap: wrap; }
    .inline-fields { display: grid; grid-template-columns: repeat(3, minmax(140px, 1fr)); gap: .6rem; }
    .toolbar { display: flex; align-items: center; justify-content: space-between; gap: .75rem; flex-wrap: wrap; }
    .toast { position: fixed; right: 1rem; bottom: 1rem; max-width: min(420px, calc(100vw - 2rem)); padding: .85rem 1rem; border-radius: 12px; background: #0f172a; color: #fff; box-shadow: var(--shadow); opacity: 0; transform: translateY(10px); pointer-events: none; transition: opacity .18s, transform .18s; z-index: 10; }
    .toast.show { opacity: 1; transform: translateY(0); }
    .toast.error { background: #991b1b; }
    @media (max-width: 820px) { main { width: min(100% - 20px, 1180px); padding-top: 1rem; } .hero, .toolbar { align-items: flex-start; flex-direction: column; } .two-col, .inline-fields { grid-template-columns: 1fr; } }
  </style>
</head>
<body><main>
  <div class="hero">
    <div>
      <h1>Gemini Router 管理</h1>
      <p>统一管理 Gemini Key、代理设置、请求日志与自动清理策略。</p>
    </div>
    <a class="logout" href="/logout">退出登录</a>
  </div>
  <div id="toast" class="toast" role="status" aria-live="polite"></div>
  {{if .Msg}}<p class="msg">{{.Msg}}</p>{{end}}

  <div class="grid two-col">
    <section>
      <h2>项目配置</h2>
      <p class="muted">项目 API Key 用于访问代理接口，也用于登录管理页。留空表示不鉴权。</p>
      <form method="post" action="/admin/project" data-ajax data-refresh="true">
        <label>项目 API Key</label>
        <input name="project_api_key" value="{{.Config.ProjectAPIKey}}" placeholder="例如 my-router-secret">
        <label>项目默认 SOCKS5 代理</label>
        <input name="project_proxy" value="{{.Config.ProjectProxy}}" placeholder="socks5://127.0.0.1:1080">
        <label>官方 API 出错自动重试次数</label>
        <input type="number" name="auto_retry" value="{{.Config.AutoRetry}}" min="0" max="5" step="1">
        <p class="muted">默认 0，范围 0-5；每次重试会自动切换到下一个可用 Gemini Key。</p>
        <button>保存项目配置</button>
      </form>
    </section>

    <section>
      <h2>添加 Gemini Key</h2>
      <form method="post" action="/admin/keys/add" data-ajax data-refresh="true" data-reset="true">
        <label>Gemini API Key（每行一个，支持批量添加）</label>
        <textarea name="keys" placeholder="AIza...&#10;AIza..."></textarea>
        <label>这些 Key 的备注（可选）</label>
        <input name="remark" placeholder="例如 生产环境、备用 Key、来源账号">
        <label>这些 Key 的单独 SOCKS5 代理（可选）</label>
        <input name="proxy" placeholder="socks5://user:pass@host:1080">
        <button>添加 Key</button>
      </form>
    </section>
  </div>

  <section>
    <div class="toolbar">
      <div>
        <h2>Gemini Key 管理</h2>
        <p class="muted">保存、测试和删除操作将通过 Ajax 完成，不会整页刷新。</p>
      </div>
      <form method="post" action="/admin/keys/test-all" data-ajax data-refresh="true"><button class="secondary">测试全部 Key</button></form>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>ID</th><th>Key</th><th>配置</th><th>测试状态</th><th>操作</th></tr></thead>
        <tbody>
        {{range .Config.GeminiKeys}}
        <tr>
          <td>{{.ID}}</td>
          <td><code>{{mask .Key}}</code></td>
          <td>
            <form id="key-update-{{.ID}}" method="post" action="/admin/keys/update" data-ajax data-refresh="true">
              <input type="hidden" name="id" value="{{.ID}}">
              <div class="inline-fields">
                <div><label>名称</label><input name="name" value="{{.Name}}"></div>
                <div><label>备注</label><input name="remark" value="{{.Remark}}" placeholder="可填写用途或来源"></div>
                <div><label>SOCKS5 代理</label><input name="proxy" value="{{.Proxy}}" placeholder="留空使用项目默认代理"></div>
              </div>
            </form>
          </td>
          <td>{{testStatus .}}</td>
          <td class="row-actions">
            <button form="key-update-{{.ID}}">保存</button>
            <form method="post" action="/admin/keys/test" data-ajax data-refresh="true"><input type="hidden" name="id" value="{{.ID}}"><button class="secondary">测试</button></form>
            <form method="post" action="/admin/keys/delete" data-ajax data-refresh="true" data-confirm="确认删除？"><input type="hidden" name="id" value="{{.ID}}"><button class="danger">删除</button></form>
          </td>
        </tr>
        {{else}}
        <tr><td colspan="5">暂无 Gemini Key</td></tr>
        {{end}}
        </tbody>
      </table>
    </div>
  </section>

  <section>
    <div class="toolbar">
      <div>
        <h2>请求日志</h2>
        <p class="muted">记录最近代理请求；敏感查询参数会被脱敏。</p>
      </div>
      <form method="post" action="/admin/logs/clear" data-ajax data-refresh="true" data-confirm="确认清空全部请求日志？"><button class="danger">清空请求日志</button></form>
    </div>
    <form method="post" action="/admin/logs/retention" data-ajax data-refresh="true">
      <label>日志保留天数（0 表示不自动清理，最大 365）</label>
      <input type="number" name="log_retention_day" value="{{.Config.LogRetentionDay}}" min="0" max="365" step="1">
      <button>保存清理策略</button>
    </form>
    <div class="table-wrap">
      <table>
        <thead><tr><th>时间</th><th>方法</th><th>路径</th><th>客户端 IP</th><th>状态</th><th>Key</th><th>重试</th><th>耗时</th><th>错误</th></tr></thead>
        <tbody>
        {{range .Logs}}
        <tr>
          <td>{{.Time}}</td>
          <td>{{.Method}}</td>
          <td><code>{{.Path}}</code></td>
          <td>{{.ClientIP}}</td>
          <td>{{.StatusCode}}</td>
          <td>{{.KeyName}}</td>
          <td>{{.Attempts}}</td>
          <td>{{.DurationMS}} ms</td>
          <td>{{.Error}}</td>
        </tr>
        {{else}}
        <tr><td colspan="9">暂无请求日志</td></tr>
        {{end}}
        </tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>代理调用示例</h2>
    <pre><code>curl -H 'X-API-Key: {{.Config.ProjectAPIKey}}' \
  http://localhost:8080/v1beta/models</code></pre>
  </section>
</main>
<script>
(function () {
  function toast(message, isError) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = message;
    el.classList.toggle('error', Boolean(isError));
    el.classList.add('show');
    window.clearTimeout(el._timer);
    el._timer = window.setTimeout(() => el.classList.remove('show'), 2400);
  }

  async function refreshMain() {
    const resp = await fetch('/admin', { headers: { 'X-Requested-With': 'fetch' } });
    if (!resp.ok) throw new Error('刷新页面数据失败');
    const html = await resp.text();
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const nextMain = doc.querySelector('main');
    const main = document.querySelector('main');
    if (nextMain && main) main.innerHTML = nextMain.innerHTML;
  }

  document.addEventListener('submit', async function (event) {
    const form = event.target.closest('form[data-ajax]');
    if (!form) return;
    event.preventDefault();
    if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) return;
    const submitter = event.submitter || form.querySelector('button');
    if (submitter) submitter.disabled = true;
    try {
      const resp = await fetch(form.action, {
        method: form.method || 'POST',
        body: new FormData(form),
        headers: { 'Accept': 'application/json', 'X-Requested-With': 'fetch' }
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(data.message || '操作失败');
      if (form.dataset.reset === 'true') form.reset();
      if (form.dataset.refresh === 'true') await refreshMain();
      toast(data.message || '操作已完成');
    } catch (err) {
      toast(err.message || '操作失败', true);
    } finally {
      if (submitter) submitter.disabled = false;
    }
  });
})();
</script>
</body></html>`

const loginHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gemini Router 登录</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f7f7fb; color: #1f2937; }
    main { width: min(92vw, 420px); background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 1.5rem; box-shadow: 0 1px 3px #0001; }
    label { display: block; margin: .75rem 0 .25rem; font-weight: 600; }
    input { width: 100%; box-sizing: border-box; padding: .65rem; border: 1px solid #d1d5db; border-radius: 8px; }
    button { width: 100%; background: #2563eb; color: white; border: 0; padding: .7rem .9rem; border-radius: 8px; cursor: pointer; margin-top: 1rem; }
    .msg { color: #dc2626; font-weight: 600; }
    .muted { color: #6b7280; font-size: .92rem; }
  </style>
</head>
<body><main>
  <h1>Gemini Router 登录</h1>
  <p class="muted">请输入项目 API Key 进入管理页面。</p>
  {{if .Msg}}<p class="msg">项目 API Key 不正确，请重试。</p>{{end}}
  <form method="post" action="/login">
    <label>项目 API Key</label>
    <input type="password" name="project_api_key" autocomplete="current-password" autofocus required>
    <button>登录</button>
  </form>
</main></body></html>`
