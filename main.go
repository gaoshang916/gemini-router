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

const adminHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gemini Router</title>
  <link href="https://cdn.jsdelivr.net/npm/geist@1.0.0/dist/fonts/geist-sans/style.css" rel="stylesheet">
  <style>
    :root {
      --bg:#FAF9F5; --card:#fff; --fg:#000; --fg-muted:#666; --fg-subtle:#999;
      --border:#e5e5e5; --radius:6px; --radius-xl:14px;
      --success:#059669; --success-bg:#ecfdf5; --error:#dc2626; --error-bg:#fef2f2;
      --shadow-md:0 4px 16px rgba(0,0,0,.08); --shadow-lg:0 20px 50px rgba(0,0,0,.08);
      --font-sans:'Geist Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:var(--font-sans);background:var(--bg);color:var(--fg);line-height:1.5;-webkit-font-smoothing:antialiased;min-height:100vh}
    a{color:inherit;text-decoration:none}
    button,input,textarea,select{font:inherit;border:none;outline:none;background:none;color:inherit}
    button{cursor:pointer}

    /* ── Header ── */
    .admin-header{background:#FAF9F5;position:fixed;top:0;left:0;right:0;z-index:100}
    .admin-header-inner{max-width:1280px;width:100%;height:54px;margin:0 auto;padding:0 28px;display:flex;align-items:center;justify-content:space-between;gap:16px}
    .admin-brand{display:flex;align-items:center;gap:8px;font-size:14px;font-weight:700;white-space:nowrap}
    .admin-brand svg{width:16px;height:16px}
    .admin-header-right{display:flex;align-items:center;gap:8px}
    .admin-header-right a{font-size:13px;color:var(--fg-muted);font-weight:500;transition:color .15s}
    .admin-header-right a:hover{color:var(--fg)}

    /* ── Layout ── */
    .admin-main{max-width:1280px;margin:0 auto;padding:78px 28px 24px}
    .page-hd{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px}
    .page-title{font-size:22px;font-weight:700;line-height:1.2}
    .page-sub{font-size:13px;color:var(--fg-muted);margin-top:5px}
    .page-actions{display:flex;gap:8px;align-items:center;flex-shrink:0}

    /* ── Stats ── */
    .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
    @media(max-width:820px){.stat-grid{grid-template-columns:repeat(2,1fr)}}
    @media(max-width:480px){.stat-grid{grid-template-columns:1fr}}
    .stat-cell{min-height:80px;padding:14px 16px;border-radius:12px;background:var(--card);display:flex;flex-direction:column;gap:10px}
    .stat-top{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .stat-label{font-size:11px;color:var(--fg-subtle);letter-spacing:.01em;white-space:nowrap}
    .stat-icon{width:24px;height:24px;display:inline-flex;align-items:center;justify-content:center;color:#a3a3a3;flex:0 0 auto}
    .stat-icon svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
    .stat-num{font-size:22px;font-weight:600;line-height:1;letter-spacing:-.02em;margin-top:auto}

    /* ── Section heading ── */
    .section-head{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin:28px 0 14px}
    .section-title{font-size:13px;font-weight:600;color:#222;letter-spacing:.01em}
    .section-title-row{display:inline-flex;align-items:center;gap:8px}
    .section-count-badge{min-width:20px;height:20px;padding:0 7px;border-radius:999px;display:inline-flex;align-items:center;justify-content:center;background:#f1ece2;color:#6a6459;font-size:11px;font-weight:600;font-variant-numeric:tabular-nums;line-height:1}

    /* ── Cards ── */
    .card{background:var(--card);border-radius:var(--radius-xl);padding:20px;box-shadow:var(--shadow-md)}
    .card+.card{margin-top:16px}
    .card h3{font-size:14px;font-weight:600;margin-bottom:4px}
    .card-desc{font-size:12px;color:var(--fg-muted);margin-bottom:14px}
    .card-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    @media(max-width:820px){.card-grid{grid-template-columns:1fr}}

    /* ── Form ── */
    .form-group{margin-bottom:12px}
    .form-label{display:block;font-size:12px;font-weight:600;color:var(--fg-muted);margin-bottom:5px}
    .form-input{width:100%;height:34px;padding:0 10px;font-size:13px;border-radius:8px;border:1px solid var(--border);background:var(--card);transition:border-color .15s}
    .form-input:focus{border-color:#bbb;box-shadow:0 0 0 2px rgba(0,0,0,.04)}
    .form-input::placeholder{color:var(--fg-subtle)}
    textarea.form-input{min-height:100px;padding:10px;resize:vertical;height:auto}
    .form-hint{font-size:11px;color:var(--fg-subtle);margin-top:4px}

    /* ── Buttons ── */
    .btn{height:32px;padding:0 14px;border-radius:8px;font-size:13px;font-weight:600;display:inline-flex;align-items:center;justify-content:center;gap:6px;transition:opacity .15s;white-space:nowrap}
    .btn-primary{background:var(--fg);color:var(--card)}
    .btn-primary:hover{opacity:.88}
    .btn-secondary{background:#f5f5f5;color:#444}
    .btn-secondary:hover{background:#eee}
    .btn-danger{background:#fef2f2;color:#b42318}
    .btn-danger:hover{background:#feeceb}
    .btn-sm{height:28px;padding:0 12px;font-size:12px;border-radius:6px}
    .btn:disabled{opacity:.5;cursor:default}

    /* ── Table ── */
    .table-card{background:var(--card);border-radius:var(--radius-xl);overflow-x:auto;-webkit-overflow-scrolling:touch}
    .table-card table{width:100%;border-collapse:collapse;min-width:700px}
    .table-card th{font-size:11px;font-weight:500;color:var(--fg-subtle);padding:11px 16px;text-align:left;letter-spacing:.01em;white-space:nowrap}
    .table-card th:last-child{text-align:right}
    .table-card td{font-size:13px;padding:13px 16px;vertical-align:middle;color:#3f3f3f}
    .table-card tr:hover td{background:#fdfdfd}
    .table-card .token-cell{font-family:ui-monospace,monospace;font-size:12px;color:#333}
    .table-card .badge{display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:999px;font-size:11px;font-weight:500}
    .badge-ok{color:#3e8f69;background:#f2f8f4}
    .badge-fail{color:#b66a63;background:#fbf3f2}
    .badge-unknown{color:#6f675d;background:#f1ece4}
    .badge-testing{color:#b47a3d;background:#fbf5ed}
    .row-actions{display:flex;align-items:center;gap:6px;justify-content:flex-end}

    /* ── Inline edit fields ── */
    .inline-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px}
    .inline-grid .form-group{margin-bottom:0}
    @media(max-width:900px){.inline-grid{grid-template-columns:1fr}}

    /* ── Code block ── */
    .code-block{background:#f7f7f7;border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-family:ui-monospace,monospace;font-size:12px;overflow-x:auto;line-height:1.6;color:#333;margin-top:8px}

    /* ── Toast ── */
    .toast-container{position:fixed;top:24px;left:50%;transform:translateX(-50%);z-index:200;display:flex;flex-direction:column;gap:10px;pointer-events:none;align-items:center}
    .toast{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;display:flex;align-items:center;gap:10px;min-width:280px;max-width:420px;pointer-events:auto;box-shadow:var(--shadow-md);animation:toastIn .3s cubic-bezier(.16,1,.3,1) forwards}
    .toast.out{animation:toastOut .2s ease forwards}
    .toast-icon{flex-shrink:0;width:20px;height:20px;display:flex;align-items:center;justify-content:center;border-radius:50%}
    .toast-success .toast-icon{background:var(--success-bg);color:var(--success)}
    .toast-error .toast-icon{background:var(--error-bg);color:var(--error)}
    .toast-content{flex:1;font-size:12px;font-weight:500}
    @keyframes toastIn{from{opacity:0;transform:translateY(16px) scale(.96)}to{opacity:1;transform:none}}
    @keyframes toastOut{from{opacity:1}to{opacity:0;transform:translateY(8px) scale(.96)}}

    @media(max-width:820px){.admin-main{padding:70px 16px 20px}.admin-header-inner{padding:0 16px}.page-hd{flex-direction:column;gap:10px}}
  </style>
</head>
<body>

<!-- ── Header ── -->
<div class="admin-header">
  <div class="admin-header-inner">
    <div class="admin-brand">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
      Gemini Router
    </div>
    <div class="admin-header-right">
      <a href="/logout">退出登录</a>
    </div>
  </div>
</div>

<!-- ── Main ── -->
<main class="admin-main">

  <!-- Toast container -->
  <div id="toast-container" class="toast-container" role="status" aria-live="polite"></div>

  <!-- Page heading -->
  <div class="page-hd">
    <div>
      <div class="page-title">Gemini Router 管理</div>
      <div class="page-sub">管理 Gemini Key、代理设置与请求日志</div>
    </div>
    <div class="page-actions">
      <form method="post" action="/admin/keys/test-all" data-ajax data-refresh="true">
        <button class="btn btn-secondary btn-sm">测试全部 Key</button>
      </form>
    </div>
  </div>

  <!-- Stats -->
  <div class="stat-grid" id="stats-grid">
    <div class="stat-cell" data-stat="total">
      <div class="stat-top">
        <div class="stat-label">Key 总数</div>
        <span class="stat-icon"><svg viewBox="0 0 24 24"><path d="M4 19a4 4 0 0 1 4-4h8a4 4 0 0 1 4 4"/><circle cx="12" cy="8" r="4"/></svg></span>
      </div>
      <div class="stat-num" id="s-total">{{len .Config.GeminiKeys}}</div>
    </div>
    <div class="stat-cell" data-stat="active">
      <div class="stat-top">
        <div class="stat-label">正常</div>
        <span class="stat-icon" style="color:#16a34a"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="m8.5 12 2.4 2.4 4.8-4.8"/></svg></span>
      </div>
      <div class="stat-num" id="s-active" style="color:#16a34a">0</div>
    </div>
    <div class="stat-cell" data-stat="failed">
      <div class="stat-top">
        <div class="stat-label">异常</div>
        <span class="stat-icon" style="color:#dc2626"><svg viewBox="0 0 24 24"><path d="m15 9-6 6m0-6 6 6"/><circle cx="12" cy="12" r="8"/></svg></span>
      </div>
      <div class="stat-num" id="s-failed" style="color:#dc2626">0</div>
    </div>
    <div class="stat-cell" data-stat="untested">
      <div class="stat-top">
        <div class="stat-label">未测试</div>
        <span class="stat-icon" style="color:#6f675d"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M12 8v4l2 2"/></svg></span>
      </div>
      <div class="stat-num" id="s-untested" style="color:#6f675d">0</div>
    </div>
  </div>

  <!-- Project Config + Add Key -->
  <div class="card-grid">
    <div class="card">
      <h3>项目配置</h3>
      <p class="card-desc">API Key 用于代理接口鉴权与登录管理页，留空则不鉴权。</p>
      <form method="post" action="/admin/project" data-ajax data-refresh="true">
        <div class="form-group">
          <label class="form-label">项目 API Key</label>
          <input class="form-input" name="project_api_key" value="{{.Config.ProjectAPIKey}}" placeholder="例如 my-router-secret">
        </div>
        <div class="form-group">
          <label class="form-label">默认 SOCKS5 代理</label>
          <input class="form-input" name="project_proxy" value="{{.Config.ProjectProxy}}" placeholder="socks5://127.0.0.1:1080">
        </div>
        <div class="form-group">
          <label class="form-label">自动重试次数</label>
          <input class="form-input" type="number" name="auto_retry" value="{{.Config.AutoRetry}}" min="0" max="5" step="1">
          <p class="form-hint">每次重试自动切到下一个可用 Key，范围 0-5</p>
        </div>
        <button class="btn btn-primary">保存项目配置</button>
      </form>
    </div>

    <div class="card">
      <h3>添加 Gemini Key</h3>
      <p class="card-desc">支持批量添加，每行一个 Key。</p>
      <form method="post" action="/admin/keys/add" data-ajax data-refresh="true" data-reset="true">
        <div class="form-group">
          <label class="form-label">Gemini API Key</label>
          <textarea class="form-input" name="keys" placeholder="AIza...&#10;AIza..." style="min-height:80px"></textarea>
        </div>
        <div class="form-group">
          <label class="form-label">备注（可选）</label>
          <input class="form-input" name="remark" placeholder="例如 生产环境、备用 Key">
        </div>
        <div class="form-group">
          <label class="form-label">单独 SOCKS5 代理（可选）</label>
          <input class="form-input" name="proxy" placeholder="socks5://user:pass@host:1080">
        </div>
        <button class="btn btn-primary">添加 Key</button>
      </form>
    </div>
  </div>

  <!-- Key Table -->
  <div class="section-head" style="margin-top:32px">
    <div class="section-title-row">
      <div class="section-title">Gemini Key 管理</div>
      <span class="section-count-badge" id="key-count">{{len .Config.GeminiKeys}}</span>
    </div>
  </div>

  <div class="table-card">
    <table>
      <thead>
        <tr><th>Key</th><th>名称</th><th>备注</th><th>代理</th><th>状态</th><th style="text-align:right">操作</th></tr>
      </thead>
      <tbody>
      {{range .Config.GeminiKeys}}
      <tr>
        <td>
          <span class="token-cell">{{mask .Key}}</span>
        </td>
        <td>
          <form id="key-update-{{.ID}}" method="post" action="/admin/keys/update" data-ajax data-refresh="true">
            <input type="hidden" name="id" value="{{.ID}}">
            <input class="form-input" name="name" value="{{.Name}}" placeholder="名称" style="width:100%;min-width:80px;height:28px;font-size:12px;padding:0 8px">
          </form>
        </td>
        <td>
          <input class="form-input" form="key-update-{{.ID}}" name="remark" value="{{.Remark}}" placeholder="用途/来源" style="width:100%;min-width:80px;height:28px;font-size:12px;padding:0 8px">
        </td>
        <td>
          <input class="form-input" form="key-update-{{.ID}}" name="proxy" value="{{.Proxy}}" placeholder="留空默认" style="width:100%;min-width:100px;height:28px;font-size:12px;padding:0 8px">
        </td>
        <td>{{testStatus .}}</td>
        <td class="row-actions">
          <button class="btn btn-secondary btn-sm" form="key-update-{{.ID}}">保存</button>
          <form method="post" action="/admin/keys/test" data-ajax data-refresh="true"><input type="hidden" name="id" value="{{.ID}}"><button class="btn btn-secondary btn-sm">测试</button></form>
          <form method="post" action="/admin/keys/delete" data-ajax data-refresh="true" data-confirm="确认删除此 Key？"><input type="hidden" name="id" value="{{.ID}}"><button class="btn btn-danger btn-sm">删除</button></form>
        </td>
      </tr>
      {{else}}
      <tr><td colspan="6" style="text-align:center;padding:40px 16px;color:var(--fg-subtle);font-size:13px">暂无 Gemini Key</td></tr>
      {{end}}
      </tbody>
    </table>
  </div>

  <!-- Logs -->
  <div class="section-head" style="margin-top:32px">
    <div class="section-title">请求日志</div>
    <form method="post" action="/admin/logs/clear" data-ajax data-refresh="true" data-confirm="确认清空全部请求日志？">
      <button class="btn btn-danger btn-sm">清空日志</button>
    </form>
  </div>

  <div class="card" style="margin-bottom:16px">
    <form method="post" action="/admin/logs/retention" data-ajax data-refresh="true" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <label class="form-label" style="margin:0;white-space:nowrap">日志保留天数</label>
      <input class="form-input" type="number" name="log_retention_day" value="{{.Config.LogRetentionDay}}" min="0" max="365" step="1" style="width:80px;height:28px;font-size:12px;padding:0 8px">
      <p class="form-hint" style="margin:0">0 表示不自动清理</p>
      <button class="btn btn-secondary btn-sm">保存</button>
    </form>
  </div>

  <div class="table-card">
    <table>
      <thead>
        <tr><th>时间</th><th>方法</th><th>路径</th><th>客户端 IP</th><th>状态</th><th>Key</th><th>重试</th><th>耗时</th><th>错误</th></tr>
      </thead>
      <tbody>
      {{range .Logs}}
      <tr>
        <td style="white-space:nowrap;font-size:12px">{{.Time}}</td>
        <td><span class="token-cell">{{.Method}}</span></td>
        <td><span class="token-cell">{{.Path}}</span></td>
        <td style="font-size:12px">{{.ClientIP}}</td>
        <td><span class="badge {{if eq .StatusCode 200}}badge-ok{{else if eq .StatusCode 0}}badge-unknown{{else}}badge-fail{{end}}">{{.StatusCode}}</span></td>
        <td style="font-size:12px">{{.KeyName}}</td>
        <td style="font-size:12px">{{.Attempts}}</td>
        <td style="font-size:12px;white-space:nowrap">{{.DurationMS}} ms</td>
        <td style="font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis">{{.Error}}</td>
      </tr>
      {{else}}
      <tr><td colspan="9" style="text-align:center;padding:40px 16px;color:var(--fg-subtle);font-size:13px">暂无请求日志</td></tr>
      {{end}}
      </tbody>
    </table>
  </div>

  <!-- API Example -->
  <div class="section-head" style="margin-top:32px">
    <div class="section-title">代理调用示例</div>
  </div>
  <div class="code-block">curl -H 'X-API-Key: {{.Config.ProjectAPIKey}}' \
  http://localhost:8080/v1beta/models</div>

</main>

<script>
(function() {
  /* ── Toast system ── */
  const container = document.getElementById('toast-container');
  let toastId = 0;

  function showToast(message, type) {
    type = type || 'success';
    const id = ++toastId;
    const icon = type === 'success'
      ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>'
      : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
    const el = document.createElement('div');
    el.className = 'toast toast-' + type;
    el.dataset.tid = id;
    el.innerHTML = '<span class="toast-icon">' + icon + '</span><span class="toast-content">' + escapeHtml(message) + '</span>';
    container.appendChild(el);
    window.setTimeout(function() {
      el.classList.add('out');
      window.setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 220);
    }, 2500);
  }

  function escapeHtml(s) {
    if (typeof s !== 'string') return String(s || '');
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  /* ── Refresh page content ── */
  async function refreshMain() {
    const resp = await fetch('/admin', { headers: { 'X-Requested-With': 'fetch' } });
    if (!resp.ok) throw new Error('刷新页面数据失败: ' + resp.status);
    const html = await resp.text();
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const nextMain = doc.querySelector('.admin-main');
    const main = document.querySelector('.admin-main');
    if (nextMain && main) main.innerHTML = nextMain.innerHTML;
  }

  /* ── Stats updater ── */
  function computeStats() {
    const table = document.querySelector('.table-card table tbody');
    if (!table) return;
    const rows = table.querySelectorAll('tr');
    if (rows.length === 0 || (rows.length === 1 && rows[0].querySelector('td') && rows[0].querySelector('td').colSpan > 1)) {
      document.getElementById('s-total').textContent = '0';
      document.getElementById('s-active').textContent = '0';
      document.getElementById('s-failed').textContent = '0';
      document.getElementById('s-untested').textContent = '0';
      return;
    }
    let total = 0, active = 0, failed = 0, untested = 0;
    rows.forEach(function(tr) {
      const statusCell = tr.querySelectorAll('td')[4];
      if (!statusCell) return;
      const text = statusCell.textContent.trim();
      total++;
      if (text === '正常' || text === '可用') active++;
      else if (text === '失败' || text === '异常' || text === '不可用') failed++;
      else untested++;
    });
    document.getElementById('s-total').textContent = total;
    document.getElementById('s-active').textContent = active;
    document.getElementById('s-failed').textContent = failed;
    document.getElementById('s-untested').textContent = untested;
    var countEl = document.getElementById('key-count');
    if (countEl) countEl.textContent = total;
  }

  /* ── Form AJAX submission ── */
  document.addEventListener('submit', async function(event) {
    var form = event.target.closest('form[data-ajax]');
    if (!form) return;
    event.preventDefault();
    var msg = form.dataset.confirm;
    if (msg && !window.confirm(msg)) return;
    var submitter = event.submitter || form.querySelector('.btn, button');
    if (submitter) submitter.disabled = true;
    try {
      var resp = await fetch(form.action, {
        method: form.method || 'POST',
        body: new FormData(form),
        headers: { 'Accept': 'application/json', 'X-Requested-With': 'fetch' }
      });
      var data = {};
      try { data = await resp.json(); } catch(e) {}
      if (!resp.ok) throw new Error(data.message || '请求失败 (' + resp.status + ')');
      if (form.dataset.reset === 'true') form.reset();
      if (form.dataset.refresh === 'true') await refreshMain();
      showToast(data.message || '操作成功', 'success');
      computeStats();
    } catch(err) {
      showToast(err.message || '操作失败', 'error');
    } finally {
      if (submitter) submitter.disabled = false;
    }
  });

  /* ── Initial stats ── */
  window.setTimeout(computeStats, 100);
})();
</script>
</body>
</html>`

const loginHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gemini Router 登录</title>
  <link href="https://cdn.jsdelivr.net/npm/geist@1.0.0/dist/fonts/geist-sans/style.css" rel="stylesheet">
  <style>
    :root{--bg-card:#fff;--fg:#000;--fg-muted:#666;--fg-subtle:#999;--border:#e5e5e5;--radius-xl:14px;--shadow-lg:0 20px 50px rgba(0,0,0,.08);--font-sans:'Geist Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:var(--font-sans);min-height:100vh;display:flex;align-items:center;justify-content:center;background:#FAF9F5;-webkit-font-smoothing:antialiased}
    .login-shell{width:min(420px,92vw);padding:24px}
    .login-card{background:var(--bg-card);border:1px solid transparent;border-radius:var(--radius-xl);padding:22px;box-shadow:var(--shadow-lg);transition:border-color .2s}
    .login-card:hover{border-color:var(--fg)}
    .login-brand{display:flex;align-items:center;gap:8px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--fg-muted);font-weight:600}
    .login-brand svg{width:14px;height:14px}
    .login-title{margin-top:8px;font-size:18px;font-weight:600}
    .login-subtitle{margin-top:4px;font-size:12px;color:var(--fg-muted)}
    .login-form{margin-top:18px;display:grid;gap:10px}
    .input{width:100%;height:34px;padding:0 10px;font-size:13px;border-radius:8px;border:1px solid var(--border);background:var(--bg-card);transition:border-color .15s}
    .input:focus{border-color:#bbb;box-shadow:0 0 0 2px rgba(0,0,0,.04)}
    .input::placeholder{color:var(--fg-subtle)}
    .btn{height:34px;padding:0 14px;border-radius:8px;font-size:13px;font-weight:600;display:inline-flex;align-items:center;justify-content:center;transition:opacity .15s;white-space:nowrap;width:100%}
    .btn-primary{background:var(--fg);color:var(--bg-card)}
    .btn-primary:hover{opacity:.88}
    .msg-error{font-size:12px;color:#dc2626;font-weight:500;text-align:center;padding:6px 0 0}
  </style>
</head>
<body>
  <div class="login-shell">
    <div class="login-card">
      <div class="login-brand">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
        Gemini Router
      </div>
      <div class="login-title">管理后台</div>
      <div class="login-subtitle">请输入项目 API Key 以继续</div>
      {{if .Msg}}<div class="msg-error">项目 API Key 不正确，请重试</div>{{end}}
      <form class="login-form" method="post" action="/login">
        <input class="input" type="password" name="project_api_key" placeholder="后台密码" autocomplete="current-password" autofocus required>
        <button class="btn btn-primary">继续</button>
      </form>
    </div>
  </div>
</body>
</html>`
