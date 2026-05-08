package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
