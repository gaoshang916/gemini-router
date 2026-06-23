package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func newTestApp(t *testing.T, projectAPIKey string) *App {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.UpdateProject(projectAPIKey, ""); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	return &App{
		store: store,
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
