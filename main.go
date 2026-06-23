package main

import (
	"bytes"
	"context"
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
	ProjectAPIKey string      `json:"project_api_key"`
	ProjectProxy  string      `json:"project_proxy"`
	GeminiKeys    []GeminiKey `json:"gemini_keys"`
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

func (s *Store) UpdateProject(apiKey, projectProxy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.ProjectAPIKey = strings.TrimSpace(apiKey)
	s.config.ProjectProxy = strings.TrimSpace(projectProxy)
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
	geminiEndpoint string
	adminTemplate  *template.Template
	requestTimeout time.Duration
}

func main() {
	dataPath := getenv("DATA_PATH", "./data/config.json")
	store, err := NewStore(dataPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	app := &App{
		store:          store,
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
	if r.FormValue("project_api_key") != cfg.ProjectAPIKey {
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
	data := struct {
		Config Config
		Msg    string
	}{Config: a.store.Snapshot(), Msg: r.URL.Query().Get("msg")}
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
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var err error
	switch r.URL.Path {
	case "/admin/project":
		err = a.store.UpdateProject(r.FormValue("project_api_key"), r.FormValue("project_proxy"))
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin?msg=saved", http.StatusSeeOther)
}

func (a *App) handleProxy(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeProxy(w, r) {
		return
	}
	key, proxyURL, ok := a.store.NextKey()
	if !ok {
		http.Error(w, "no gemini api key configured", http.StatusServiceUnavailable)
		return
	}
	target, err := url.Parse(a.geminiEndpoint + r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	target.RawQuery = r.URL.Query().Encode()
	q := target.Query()
	q.Set("key", key.Key)
	target.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(r.Context(), a.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	copyHeaders(req.Header, r.Header)
	req.Header.Del("Host")
	req.Header.Del("Authorization")
	req.Header.Del("X-API-Key")
	req.Host = target.Host

	client, err := httpClient(proxyURL, a.requestTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("X-Gemini-Router-Key", key.Name)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func adminSessionValue(projectAPIKey string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(projectAPIKey))
}

func (a *App) authorizeProxy(w http.ResponseWriter, r *http.Request) bool {
	cfg := a.store.Snapshot()
	if cfg.ProjectAPIKey == "" {
		return true
	}
	got := r.Header.Get("X-API-Key")
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if got != cfg.ProjectAPIKey {
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
	if cookie, err := r.Cookie(adminSessionCookie); err == nil && cookie.Value == adminSessionValue(cfg.ProjectAPIKey) {
		return true
	}
	if r.Header.Get("X-API-Key") == cfg.ProjectAPIKey {
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
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; background: #f7f7fb; color: #1f2937; }
    main { max-width: 1100px; margin: auto; }
    section { background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; box-shadow: 0 1px 3px #0001; }
    label { display: block; margin: .75rem 0 .25rem; font-weight: 600; }
    input, textarea { width: 100%; box-sizing: border-box; padding: .65rem; border: 1px solid #d1d5db; border-radius: 8px; }
    textarea { min-height: 8rem; }
    button { background: #2563eb; color: white; border: 0; padding: .6rem .9rem; border-radius: 8px; cursor: pointer; margin-top: .75rem; }
    button.secondary { background: #4b5563; }
    button.danger { background: #dc2626; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: .6rem; text-align: left; vertical-align: top; }
    code { background: #f3f4f6; padding: .15rem .3rem; border-radius: 4px; }
    .msg { color: #15803d; font-weight: 600; }
    .muted { color: #6b7280; font-size: .92rem; }
    .row-actions { display: flex; gap: .4rem; flex-wrap: wrap; }
  </style>
</head>
<body><main>
  <h1>Gemini Router 管理</h1>
  <p><a href="/logout">退出登录</a></p>
  {{if .Msg}}<p class="msg">{{.Msg}}</p>{{end}}
  <section>
    <h2>项目配置</h2>
    <p class="muted">项目 API Key 用于访问代理接口，也用于登录管理页。留空表示不鉴权。</p>
    <form method="post" action="/admin/project">
      <label>项目 API Key</label>
      <input name="project_api_key" value="{{.Config.ProjectAPIKey}}" placeholder="例如 my-router-secret">
      <label>项目默认 SOCKS5 代理</label>
      <input name="project_proxy" value="{{.Config.ProjectProxy}}" placeholder="socks5://127.0.0.1:1080">
      <button>保存项目配置</button>
    </form>
  </section>

  <section>
    <h2>添加 Gemini Key</h2>
    <form method="post" action="/admin/keys/add">
      <label>Gemini API Key（每行一个，支持批量添加）</label>
      <textarea name="keys" placeholder="AIza...&#10;AIza..."></textarea>
      <label>这些 Key 的备注（可选）</label>
      <input name="remark" placeholder="例如 生产环境、备用 Key、来源账号">
      <label>这些 Key 的单独 SOCKS5 代理（可选）</label>
      <input name="proxy" placeholder="socks5://user:pass@host:1080">
      <button>添加</button>
    </form>
  </section>

  <section>
    <h2>Gemini Key 管理</h2>
    <form method="post" action="/admin/keys/test-all"><button class="secondary">测试全部 Key</button></form>
    <table>
      <thead><tr><th>ID</th><th>名称</th><th>Key</th><th>备注</th><th>SOCKS5 代理</th><th>测试状态</th><th>操作</th></tr></thead>
      <tbody>
      {{range .Config.GeminiKeys}}
      <tr>
        <td>{{.ID}}</td>
        <td>
          <form method="post" action="/admin/keys/update">
            <input type="hidden" name="id" value="{{.ID}}">
            <input name="name" value="{{.Name}}">
        </td>
        <td><code>{{mask .Key}}</code></td>
        <td><input name="remark" value="{{.Remark}}" placeholder="可填写用途或来源"></td>
        <td><input name="proxy" value="{{.Proxy}}" placeholder="留空使用项目默认代理"></td>
        <td>{{testStatus .}}</td>
        <td class="row-actions">
            <button>保存</button>
          </form>
          <form method="post" action="/admin/keys/test"><input type="hidden" name="id" value="{{.ID}}"><button class="secondary">测试</button></form>
          <form method="post" action="/admin/keys/delete" onsubmit="return confirm('确认删除？')"><input type="hidden" name="id" value="{{.ID}}"><button class="danger">删除</button></form>
        </td>
      </tr>
      {{else}}
      <tr><td colspan="7">暂无 Gemini Key</td></tr>
      {{end}}
      </tbody>
    </table>
  </section>

  <section>
    <h2>代理调用示例</h2>
    <pre><code>curl -H 'X-API-Key: {{.Config.ProjectAPIKey}}' \
  http://localhost:8080/v1beta/models</code></pre>
  </section>
</main></body></html>`

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
