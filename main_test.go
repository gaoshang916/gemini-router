package main

import (
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestApp(t *testing.T, projectAPIKey string) *App {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.UpdateProject(projectAPIKey, "", 0); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	return &App{
		store:          store,
		logStore:       NewRequestLogStore(filepath.Join(t.TempDir(), "request_logs.jsonl")),
		geminiEndpoint: "http://127.0.0.1",
		requestTimeout: 5 * time.Second,
		adminTemplate: template.Must(template.New("admin").Funcs(template.FuncMap{
			"mask":       mask,
			"testStatus": testStatus,
		}).Parse(adminHTML)),
	}
}

func TestAdminRedirectsToLoginWhenNotAuthenticated(t *testing.T) {
	app := newTestApp(t, "secret")
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rr := httptest.NewRecorder()

	app.handleAdmin(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if got := rr.Header().Get("Location"); got != "/login" {
		t.Fatalf("Location = %q, want /login", got)
	}
}

func TestLoginSetsCookieAndAllowsAdmin(t *testing.T) {
	app := newTestApp(t, "secret")
	form := url.Values{"project_api_key": {"secret"}}
	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()

	app.handleLogin(loginRR, loginReq)

	if loginRR.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want %d", loginRR.Code, http.StatusSeeOther)
	}
	cookies := loginRR.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != adminSessionCookie {
		t.Fatalf("login cookies = %#v, want %s", cookies, adminSessionCookie)
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	adminReq.AddCookie(cookies[0])
	adminRR := httptest.NewRecorder()

	app.handleAdmin(adminRR, adminReq)

	if adminRR.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want %d", adminRR.Code, http.StatusOK)
	}
}

func TestAdminKeyQueryParamNoLongerAuthenticates(t *testing.T) {
	app := newTestApp(t, "secret")
	req := httptest.NewRequest(http.MethodGet, "/admin?admin_key=secret", nil)
	rr := httptest.NewRecorder()

	app.handleAdmin(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if got := rr.Header().Get("Location"); got != "/login" {
		t.Fatalf("Location = %q, want /login", got)
	}
}

func TestStorePersistsGeminiKeyRemark(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.AddKeys([]string{"gemini-key"}, "", " production key "); err != nil {
		t.Fatalf("AddKeys: %v", err)
	}
	cfg := store.Snapshot()
	if len(cfg.GeminiKeys) != 1 {
		t.Fatalf("GeminiKeys length = %d, want 1", len(cfg.GeminiKeys))
	}
	if got := cfg.GeminiKeys[0].Remark; got != "production key" {
		t.Fatalf("Remark = %q, want production key", got)
	}
	if err := store.UpdateKey(cfg.GeminiKeys[0].ID, "key-name", "", " backup key "); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}
	cfg = store.Snapshot()
	if got := cfg.GeminiKeys[0].Remark; got != "backup key" {
		t.Fatalf("Remark after update = %q, want backup key", got)
	}
}

func TestStorePersistsAutoRetryWithClamp(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.UpdateProject("secret", "", 7); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if got := store.Snapshot().AutoRetry; got != 5 {
		t.Fatalf("AutoRetry = %d, want 5", got)
	}
	if err := store.UpdateProject("secret", "", -1); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if got := store.Snapshot().AutoRetry; got != 0 {
		t.Fatalf("AutoRetry = %d, want 0", got)
	}
}

func TestProxyRetriesWithNextKeyOnAPIError(t *testing.T) {
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		seen = append(seen, key)
		if key == "bad-key" {
			http.Error(w, "bad key", http.StatusTooManyRequests)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Upstream", "ok")
		_, _ = w.Write([]byte("key=" + key + ";body=" + string(body)))
	}))
	defer upstream.Close()

	app := newTestApp(t, "secret")
	app.geminiEndpoint = upstream.URL
	if err := app.store.UpdateProject("secret", "", 1); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if err := app.store.AddKeys([]string{"bad-key", "good-key"}, "", ""); err != nil {
		t.Fatalf("AddKeys: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1beta/models:generateContent", strings.NewReader("payload"))
	req.Header.Set("X-API-Key", "secret")
	rr := httptest.NewRecorder()

	app.handleProxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if got := rr.Body.String(); got != "key=good-key;body=payload" {
		t.Fatalf("body = %q, want successful retry body", got)
	}
	if strings.Join(seen, ",") != "bad-key,good-key" {
		t.Fatalf("seen keys = %#v, want bad-key then good-key", seen)
	}
	if got := rr.Header().Get("X-Gemini-Router-Attempts"); got != "2" {
		t.Fatalf("attempts header = %q, want 2", got)
	}
}

func TestAdminSessionValueDoesNotExposeProjectAPIKey(t *testing.T) {
	secret := "secret"
	if got := adminSessionValue(secret); got == "c2VjcmV0" || strings.Contains(got, secret) {
		t.Fatalf("adminSessionValue(%q) = %q, want opaque token", secret, got)
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "Upgrade, X-Debug")
	h.Set("Upgrade", "websocket")
	h.Set("X-Debug", "remove-me")
	h.Set("Proxy-Authorization", "secret")
	h.Set("X-Keep", "keep-me")

	removeHopByHopHeaders(h)

	for _, name := range []string{"Connection", "Upgrade", "X-Debug", "Proxy-Authorization"} {
		if got := h.Get(name); got != "" {
			t.Fatalf("%s = %q, want removed", name, got)
		}
	}
	if got := h.Get("X-Keep"); got != "keep-me" {
		t.Fatalf("X-Keep = %q, want keep-me", got)
	}
}

func TestProxyWritesRequestLog(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	app := newTestApp(t, "secret")
	app.geminiEndpoint = upstream.URL
	if err := app.store.AddKeys([]string{"gemini-key"}, "", ""); err != nil {
		t.Fatalf("AddKeys: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1beta/models?key=client-secret&alt=json", nil)
	req.Header.Set("X-API-Key", "secret")
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	rr := httptest.NewRecorder()

	app.handleProxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	logs, err := app.logStore.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("logs length = %d, want 1", len(logs))
	}
	got := logs[0]
	if got.Method != http.MethodGet || got.StatusCode != http.StatusOK || got.KeyName != "key-1" || got.Attempts != 1 {
		t.Fatalf("log = %#v, want successful request metadata", got)
	}
	if got.ClientIP != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want forwarded IP", got.ClientIP)
	}
	if strings.Contains(got.Path, "client-secret") || !strings.Contains(got.Path, "key=REDACTED") {
		t.Fatalf("Path = %q, want redacted key", got.Path)
	}
}

func TestRequestLogCleanupHonorsRetention(t *testing.T) {
	store := NewRequestLogStore(filepath.Join(t.TempDir(), "request_logs.jsonl"))
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	if err := store.Append(RequestLog{Time: now.Add(-48 * time.Hour).Format(time.RFC3339), Path: "/old"}); err != nil {
		t.Fatalf("Append old: %v", err)
	}
	if err := store.Append(RequestLog{Time: now.Add(-12 * time.Hour).Format(time.RFC3339), Path: "/new"}); err != nil {
		t.Fatalf("Append new: %v", err)
	}
	if err := store.Cleanup(1, now); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	logs, err := store.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(logs) != 1 || logs[0].Path != "/new" {
		t.Fatalf("logs = %#v, want only new log", logs)
	}
}

func TestAdminActionReturnsJSONForAjax(t *testing.T) {
	app := newTestApp(t, "secret")
	form := url.Values{
		"project_api_key": {"secret"},
		"project_proxy":   {""},
		"auto_retry":      {"2"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/project", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", "secret")
	rr := httptest.NewRecorder()

	app.handleAdminAction(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %q, want ok JSON", rr.Body.String())
	}
	if got := app.store.Snapshot().AutoRetry; got != 2 {
		t.Fatalf("AutoRetry = %d, want 2", got)
	}
}
