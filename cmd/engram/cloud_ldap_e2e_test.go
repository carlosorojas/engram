package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/internal/cloud"
	"github.com/Gentleman-Programming/engram/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/internal/cloud/cloudserver"
	engramsync "github.com/Gentleman-Programming/engram/internal/sync"
	"github.com/golang-jwt/jwt/v5"
)

// fakeStoreForE2E satisfies cloudserver.ChunkStore for the LDAP smoke test.
// /sync/pull only needs ReadManifest to return a valid (possibly empty) manifest.
type fakeStoreForE2E struct{}

func (fakeStoreForE2E) ReadManifest(context.Context, string) (*engramsync.Manifest, error) {
	return &engramsync.Manifest{}, nil
}
func (fakeStoreForE2E) WriteChunk(context.Context, string, string, string, string, []byte) error {
	return nil
}
func (fakeStoreForE2E) ReadChunk(context.Context, string, string) ([]byte, error) {
	return []byte("{}"), nil
}
func (fakeStoreForE2E) KnownSessionIDs(context.Context, string) (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}

// TestCloudServeLDAPModeEndToEnd is the Phase 5 smoke equivalent: it boots the
// real cloud server (via the same path the binary takes) in LDAP mode against
// a stub upstream, then exercises the full chain — login proxy → JWT decoded
// from upstream response → authenticated request → mapped/unmapped project
// authorization. All four spec scenarios in one test, no interactive prompts.
func TestCloudServeLDAPModeEndToEnd(t *testing.T) {
	// --- 1. Stub the 3rd-party LDAP auth service. ---------------------------
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		body, _ := io.ReadAll(r.Body)
		var creds struct{ Username, Password string }
		_ = json.Unmarshal(body, &creds)
		if creds.Username != "alice" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unknown user"}`))
			return
		}
		// Mint a JWT carrying the groups claim — same shape the real upstream returns.
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":    "alice",
			"groups": []string{"ops"},
		})
		signed, _ := tok.SignedString([]byte("upstream-secret-not-shared-with-engram"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"Login successful","token":"` + signed + `"}`))
	}))
	defer upstream.Close()

	// --- 2. Build the cloud server the same way newCloudRuntime does. ------
	groupMap, err := auth.ParseGroupMap("ops:proj-a;devs:proj-c")
	if err != nil {
		t.Fatalf("parse group map: %v", err)
	}
	ldapAuth := auth.NewLDAPAuthorizer(groupMap)
	loginProxy := auth.NewLoginProxy(upstream.URL, 5_000_000_000) // 5s
	server := cloudserver.New(
		fakeStoreForE2E{},
		ldapAuth,
		0,
		cloudserver.WithLoginProxy(loginProxy),
	)

	// --- 3. Wrap in httptest so the CLI can talk to it via HTTP. ------------
	frontend := httptest.NewServer(server.Handler())
	defer frontend.Close()

	// --- 4. Drive the runLDAPLogin core (exactly what `engram cloud login --ldap`
	//        runs after collecting credentials). -----------------------------
	cfg := newTestCfgWithDataDir(t)
	if err := runLDAPLogin(cfg, frontend.URL, "alice", "any"); err != nil {
		t.Fatalf("login flow failed: %v", err)
	}
	if upstreamHits != 1 {
		t.Fatalf("expected exactly one upstream call, got %d", upstreamHits)
	}
	stored, err := loadCloudConfig(cfg)
	if err != nil || stored == nil || stored.Token == "" {
		t.Fatalf("expected token persisted, got cfg=%+v err=%v", stored, err)
	}

	// --- 5. Use the persisted JWT to hit a MAPPED project — should 200. -----
	mappedReq, _ := http.NewRequest(http.MethodGet, frontend.URL+"/sync/pull?project=proj-a", nil)
	mappedReq.Header.Set("Authorization", "Bearer "+stored.Token)
	mappedResp, err := http.DefaultClient.Do(mappedReq)
	if err != nil {
		t.Fatalf("mapped request: %v", err)
	}
	defer mappedResp.Body.Close()
	if mappedResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(mappedResp.Body)
		t.Fatalf("expected 200 for mapped project, got %d body=%q", mappedResp.StatusCode, body)
	}

	// --- 6. Same JWT against an UNMAPPED project — should 403. --------------
	unmappedReq, _ := http.NewRequest(http.MethodGet, frontend.URL+"/sync/pull?project=proj-c", nil)
	unmappedReq.Header.Set("Authorization", "Bearer "+stored.Token)
	unmappedResp, err := http.DefaultClient.Do(unmappedReq)
	if err != nil {
		t.Fatalf("unmapped request: %v", err)
	}
	defer unmappedResp.Body.Close()
	if unmappedResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(unmappedResp.Body)
		t.Fatalf("expected 403 for unmapped project, got %d body=%q", unmappedResp.StatusCode, body)
	}

	// --- 7. Upstream rejects bad creds → CLI surfaces the error. ------------
	cfg2 := newTestCfgWithDataDir(t)
	if err := runLDAPLogin(cfg2, frontend.URL, "ghost", "any"); err == nil {
		t.Fatal("expected login failure for unknown user")
	} else if !strings.Contains(err.Error(), "unknown user") {
		t.Fatalf("expected upstream error surfaced, got %q", err.Error())
	}
}

func TestCloudServeLDAPModeUsesEnvConfig(t *testing.T) {
	// Validates that ConfigFromEnv → newCloudRuntime correctly wires LDAP mode
	// using the new env vars introduced in Phase 1.
	clearAuthEnv(t)
	t.Setenv("ENGRAM_AUTH_MODE", "ldap")
	t.Setenv("ENGRAM_AUTH_URL", "https://idp.example.com/api/v1/ldap/auth/login")
	t.Setenv("ENGRAM_AUTH_API_KEY", "k")
	t.Setenv("ENGRAM_LDAP_GROUP_MAP", "ops:proj-a")

	cfg, err := cloud.ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.AuthMode != cloud.AuthModeLDAP {
		t.Fatalf("expected AuthMode=ldap, got %q", cfg.AuthMode)
	}
	if cfg.AuthURL == "" || cfg.LDAPGroupMap == "" {
		t.Fatalf("expected env propagation, got url=%q map=%q", cfg.AuthURL, cfg.LDAPGroupMap)
	}
	if err := validateCloudServeAuthConfig(); err != nil {
		t.Fatalf("expected ldap config to validate, got %v", err)
	}
}

// ─── Phase 7: Dashboard LDAP login e2e tests ─────────────────────────────────
//
// These tests boot a real CloudServer (using fakeStoreForE2E) wired in LDAP mode
// and drive the dashboard login page through a stub upstream auth service.
// Pattern mirrors TestCloudServeLDAPModeEndToEnd above.

const testJWTSecret = "a-32-byte-secret-for-tests-12345"

// mintTestJWT creates a signed JWT using a test upstream secret.
// expOffset is added to time.Now() to set the exp claim; pass 0 to omit exp.
func mintTestJWT(t *testing.T, groups []string, expOffset time.Duration, includeExp bool) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":    "testuser",
		"groups": groups,
	}
	if includeExp {
		claims["exp"] = time.Now().Add(expOffset).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("upstream-test-secret"))
	if err != nil {
		t.Fatalf("mintTestJWT: %v", err)
	}
	return signed
}

// buildDashboardLDAPServer constructs a CloudServer in LDAP mode for dashboard
// login e2e tests. upstreamURL is the stub auth service URL.
// groupMap is in "group:project" format (e.g. "developers:*").
// jwtSecret is used for LDAPSessionCodec; rateLimitMax≤0 uses the env-var default.
func buildDashboardLDAPServer(t *testing.T, upstreamURL, groupMap, jwtSecret string, limiter auth.Limiter) *cloudserver.CloudServer {
	t.Helper()
	groupMapParsed, err := auth.ParseGroupMap(groupMap)
	if err != nil {
		t.Fatalf("ParseGroupMap: %v", err)
	}
	ldapAuth := auth.NewLDAPAuthorizer(groupMapParsed)
	loginProxy := auth.NewLoginProxy(upstreamURL, 5*time.Second)
	loginProxy.APIKey = "test"

	codec, err := auth.NewLDAPSessionCodec(jwtSecret)
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec: %v", err)
	}

	ldapLoginFunc := func(ctx context.Context, username, password string) (string, auth.UserInfo, error) {
		return loginProxy.Login(ctx, username, password)
	}

	opts := []cloudserver.Option{
		cloudserver.WithLoginProxy(loginProxy),
		cloudserver.WithLDAPSessionCodec(codec),
		cloudserver.WithLDAPLoginFunc(ldapLoginFunc),
	}
	if limiter != nil {
		opts = append(opts, cloudserver.WithLDAPLimiter(limiter))
	}

	return cloudserver.New(fakeStoreForE2E{}, ldapAuth, 0, opts...)
}

// postDashboardLogin sends a POST /dashboard/login with form credentials.
// disableRedirect makes the client NOT follow the 303 so we can inspect the raw
// response code and headers.
func postDashboardLogin(t *testing.T, serverURL, username, password string, followRedirect bool) *http.Response {
	t.Helper()
	client := &http.Client{}
	if !followRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	form := url.Values{
		"username": {username},
		"password": {password},
	}
	resp, err := client.PostForm(serverURL+"/dashboard/login", form)
	if err != nil {
		t.Fatalf("POST /dashboard/login: %v", err)
	}
	return resp
}

// TestLDAPDashboardLogin_GoldenPath — 7.1 RED
// Full server + stub upstream → POST /dashboard/login → 303 + Set-Cookie with non-zero MaxAge.
func TestLDAPDashboardLogin_GoldenPath(t *testing.T) {
	// Stub upstream: returns valid JWT with exp=now+3600 and groups=["developers"].
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &creds)
		if creds.Username != "alice" || creds.Password != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad credentials"}`))
			return
		}
		signed := mintTestJWT(t, []string{"developers"}, 3600*time.Second, true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","token":%q,"user":{"uid":"alice","cn":"Alice Smith"}}`, signed)
	}))
	defer upstream.Close()

	srv := buildDashboardLDAPServer(t, upstream.URL, "developers:*", testJWTSecret, nil)
	frontend := httptest.NewServer(srv.Handler())
	defer frontend.Close()

	resp := postDashboardLogin(t, frontend.URL, "alice", "secret", false)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 303, got %d body=%q", resp.StatusCode, body)
	}
	cookies := resp.Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "engram_dashboard_token" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected Set-Cookie for engram_dashboard_token, got none")
	}
	if sessionCookie.MaxAge <= 0 {
		t.Fatalf("expected MaxAge > 0, got %d", sessionCookie.MaxAge)
	}
}

// TestLDAPDashboardLogin_WrongPassword — 7.2 RED
// Stub upstream returns 401 → 200 + LDAPLoginPage with error rendered, NO Set-Cookie.
func TestLDAPDashboardLogin_WrongPassword(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer upstream.Close()

	srv := buildDashboardLDAPServer(t, upstream.URL, "developers:*", testJWTSecret, nil)
	frontend := httptest.NewServer(srv.Handler())
	defer frontend.Close()

	resp := postDashboardLogin(t, frontend.URL, "alice", "wrongpassword", true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with error form, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(resp.Cookies()) > 0 {
		t.Fatal("expected no Set-Cookie on failed login, but got cookies")
	}
	// Verify no session cookie in response headers.
	for _, c := range resp.Cookies() {
		if c.Name == "engram_dashboard_token" {
			t.Fatal("expected no session cookie on bad credentials")
		}
	}
	// Body should contain the error form (username input field present).
	if !strings.Contains(string(body), "username") {
		t.Fatalf("expected login form in body, got: %q", string(body)[:min(len(string(body)), 500)])
	}
}

// TestLDAPDashboardLogin_RateLimitE2E — 7.3 RED
// 11 POSTs from same IP → 11th is 429 + Retry-After header.
// Uses a tight limiter (max=10, window=60s) via WithLDAPLimiter.
func TestLDAPDashboardLogin_RateLimitE2E(t *testing.T) {
	// Stub upstream: always returns 401 (we only care about rate limiting, not auth success).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad credentials"}`))
	}))
	defer upstream.Close()

	limiter := auth.NewSlidingWindowLimiter(10, 60*time.Second, nil)
	srv := buildDashboardLDAPServer(t, upstream.URL, "developers:*", testJWTSecret, limiter)
	frontend := httptest.NewServer(srv.Handler())
	defer frontend.Close()

	// Send 10 requests — all should be let through (200 with error form).
	for i := 0; i < 10; i++ {
		resp := postDashboardLogin(t, frontend.URL, "alice", "wrong", true)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d should not be rate-limited, got 429 body=%q", i+1, body)
		}
	}

	// 11th request must be 429.
	resp11 := postDashboardLogin(t, frontend.URL, "alice", "wrong", true)
	defer resp11.Body.Close()
	if resp11.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp11.Body)
		t.Fatalf("expected 429 on 11th request, got %d body=%q", resp11.StatusCode, body)
	}
	retryAfter := resp11.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected Retry-After header on 429 response, got none")
	}
}

// TestLDAPDashboardLogin_MissingExp — 7.4 RED
// Stub upstream returns a JWT WITHOUT exp claim → form re-renders with error, NO cookie.
func TestLDAPDashboardLogin_MissingExp(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mint JWT with no exp claim.
		signed := mintTestJWT(t, []string{"developers"}, 0, false /* no exp */)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","token":%q}`, signed)
	}))
	defer upstream.Close()

	srv := buildDashboardLDAPServer(t, upstream.URL, "developers:*", testJWTSecret, nil)
	frontend := httptest.NewServer(srv.Handler())
	defer frontend.Close()

	resp := postDashboardLogin(t, frontend.URL, "alice", "secret", true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with error form, got %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "engram_dashboard_token" {
			t.Fatal("expected no session cookie when JWT has no exp, got one")
		}
	}
	body, _ := io.ReadAll(resp.Body)
	// Form should be re-rendered — verify it contains a form input.
	if !strings.Contains(string(body), "username") {
		t.Fatalf("expected login form re-render, got body: %q", string(body)[:min(len(string(body)), 500)])
	}
}

// TestLDAPDashboardLogin_NoMappedGroup — 7.5 RED
// Stub returns valid JWT but groups claim is empty → LDAPAuthorizer rejects
// via ErrLDAPNoAuthorizedGroups → form re-renders with error, NO cookie.
func TestLDAPDashboardLogin_NoMappedGroup(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mint JWT with empty groups claim — no mapped group in "developers:*".
		signed := mintTestJWT(t, []string{} /* empty groups */, 3600*time.Second, true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","token":%q}`, signed)
	}))
	defer upstream.Close()

	// Group map: developers → *; empty groups JWT won't match.
	srv := buildDashboardLDAPServer(t, upstream.URL, "developers:*", testJWTSecret, nil)
	frontend := httptest.NewServer(srv.Handler())
	defer frontend.Close()

	resp := postDashboardLogin(t, frontend.URL, "alice", "secret", true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with error form, got %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "engram_dashboard_token" {
			t.Fatal("expected no session cookie when group not mapped, got one")
		}
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "username") {
		t.Fatalf("expected login form re-render, got body: %q", string(body)[:min(len(string(body)), 500)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
