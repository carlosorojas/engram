package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/internal/cloud/cloudserver"
)

// buildTokenModeServer constructs a CloudServer in token mode (no LDAP options).
// It wires auth.Service with a static bearer token and a project allowlist.
// No WithLDAPSessionCodec, WithLDAPLoginFunc, WithLoginProxy, WithLDAPLimiter,
// or WithLDAPAdminGroups options are used — this is the pure legacy token path.
func buildTokenModeServer(t *testing.T, staticToken string, allowedProjects []string) *cloudserver.CloudServer {
	t.Helper()
	authSvc, err := auth.NewService(nil, "a-32-byte-secret-for-tests-12345")
	if err != nil {
		t.Fatalf("auth.NewService: %v", err)
	}
	authSvc.SetBearerToken(staticToken)
	authSvc.SetAllowedProjects(allowedProjects)
	return cloudserver.New(
		fakeStoreForE2E{},
		authSvc,
		0,
		cloudserver.WithProjectAuthorizer(authSvc),
	)
}

// TestCloudServerTokenModeE2E_LegacyPathStillWorks is the Phase 10 regression
// net for the static-token auth path. It verifies that the LDAP work introduced
// in Phase 5-9 did not break any part of the legacy token-mode server:
//
//   - Dashboard login page renders the token form (NOT the LDAP username/password form)
//   - /sync/pull with valid token + mapped project → 200
//   - /sync/pull with wrong token → 401
//   - /sync/pull with no Authorization header → 401
//   - /sync/pull with valid token but unmapped project → 403
//   - POST /auth/ldap/login → 404 (LDAP route not mounted in token mode)
func TestCloudServerTokenModeE2E_LegacyPathStillWorks(t *testing.T) {
	const staticToken = "test-static-token"
	const allowedProject = "proj-a"

	srv := buildTokenModeServer(t, staticToken, []string{allowedProject})
	frontend := httptest.NewServer(srv.Handler())
	defer frontend.Close()

	client := &http.Client{
		// Do not follow redirects — we want to inspect raw responses.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// ─── 1. Dashboard login page renders the token form ─────────────────────
	t.Run("dashboard_login_renders_token_form", func(t *testing.T) {
		resp, err := client.Get(frontend.URL + "/dashboard/login")
		if err != nil {
			t.Fatalf("GET /dashboard/login: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, `name="token"`) {
			t.Errorf("expected token form field (name=\"token\") in login page body")
		}
		if strings.Contains(bodyStr, `name="username"`) {
			t.Errorf("expected NO username field in token-mode login page, but found one")
		}
	})

	// ─── 2. Valid token + mapped project → 200 ──────────────────────────────
	t.Run("valid_token_mapped_project_200", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/sync/pull?project="+allowedProject, nil)
		req.Header.Set("Authorization", "Bearer "+staticToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /sync/pull: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected non-401/403 for valid token + mapped project, got %d body=%q",
				resp.StatusCode, body)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d body=%q", resp.StatusCode, body)
		}
	})

	// ─── 3. Wrong token → 401 ───────────────────────────────────────────────
	t.Run("wrong_token_401", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/sync/pull?project="+allowedProject, nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /sync/pull: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 401 for wrong token, got %d body=%q", resp.StatusCode, body)
		}
	})

	// ─── 4. No Authorization header → 401 ───────────────────────────────────
	t.Run("no_auth_header_401", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/sync/pull?project="+allowedProject, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /sync/pull: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 401 with no Authorization header, got %d body=%q", resp.StatusCode, body)
		}
	})

	// ─── 5. Valid token + unmapped project → 403 ────────────────────────────
	t.Run("valid_token_unmapped_project_403", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/sync/pull?project=unmapped-project", nil)
		req.Header.Set("Authorization", "Bearer "+staticToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /sync/pull: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 403 for unmapped project, got %d body=%q", resp.StatusCode, body)
		}
	})

	// ─── 6. POST /auth/ldap/login → 404 (LDAP route not mounted) ────────────
	t.Run("ldap_login_route_absent_404", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, frontend.URL+"/auth/ldap/login",
			strings.NewReader(`{"username":"alice","password":"secret"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST /auth/ldap/login: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 404 for /auth/ldap/login in token mode, got %d body=%q",
				resp.StatusCode, body)
		}
	})
}

// TestResolveCloudRuntimeConfig_TokenResolutionOrder verifies the token
// resolution priority introduced for the LDAP login path:
//
//   - ENGRAM_CLOUD_TOKEN env var wins when set (explicit override)
//   - Persisted cloud.json token is used as fallback when env is unset
//
// This is a unit test for main.go:resolveCloudRuntimeConfig, kept separate from
// the e2e harness above.
func TestResolveCloudRuntimeConfig_TokenResolutionOrder(t *testing.T) {
	t.Run("env_wins_over_persisted", func(t *testing.T) {
		cfg := newTestCfgWithDataDir(t)
		if err := saveCloudConfig(cfg, &cloudConfig{
			ServerURL: "http://x.example",
			Token:     "from-disk",
		}); err != nil {
			t.Fatalf("saveCloudConfig: %v", err)
		}
		t.Setenv("ENGRAM_CLOUD_TOKEN", "from-env")

		cc, err := resolveCloudRuntimeConfig(cfg)
		if err != nil {
			t.Fatalf("resolveCloudRuntimeConfig: %v", err)
		}
		if cc.Token != "from-env" {
			t.Errorf("expected env token to win, got %q", cc.Token)
		}
	})

	t.Run("persisted_used_when_env_unset", func(t *testing.T) {
		cfg := newTestCfgWithDataDir(t)
		if err := saveCloudConfig(cfg, &cloudConfig{
			ServerURL: "http://x.example",
			Token:     "from-disk",
		}); err != nil {
			t.Fatalf("saveCloudConfig: %v", err)
		}
		t.Setenv("ENGRAM_CLOUD_TOKEN", "") // explicitly unset

		cc, err := resolveCloudRuntimeConfig(cfg)
		if err != nil {
			t.Fatalf("resolveCloudRuntimeConfig: %v", err)
		}
		if cc.Token != "from-disk" {
			t.Errorf("expected persisted token as fallback, got %q", cc.Token)
		}
	})
}
