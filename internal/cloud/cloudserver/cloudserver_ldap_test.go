package cloudserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	cloudauth "github.com/Gentleman-Programming/engram/internal/cloud/auth"
	"github.com/golang-jwt/jwt/v5"
)

func mintTestJWTForCloud(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("test-key-decoded-only-by-engram"))
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	return signed
}

func TestLDAPLoginProxyForwardsToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"Login successful","token":"eyJUEST"}`))
	}))
	defer upstream.Close()

	proxy := cloudauth.NewLoginProxy(upstream.URL, 5*time.Second)
	authz := cloudauth.NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	srv := New(&fakeStore{}, authz, 0, WithLoginProxy(proxy))

	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(`{"username":"alice","password":"s3cret"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"token":"eyJUEST"`) {
		t.Fatalf("expected upstream token verbatim, got %q", rec.Body.String())
	}
}

func TestLDAPLoginProxyAbsentInTokenMode(t *testing.T) {
	srv := New(&fakeStore{}, fakeAuth{}, 0)
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 in token mode, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestLDAPModeAuthorizesMappedProject(t *testing.T) {
	authz := cloudauth.NewLDAPAuthorizer(map[string][]string{
		"ops": {"proj-a"},
	})
	srv := New(&fakeStore{}, authz, 0)

	token := mintTestJWTForCloud(t, jwt.MapClaims{"groups": []string{"ops"}})
	req := httptest.NewRequest(http.MethodGet, "/sync/pull?project=proj-a", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for mapped project, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestLDAPModeRejectsUnmappedProject(t *testing.T) {
	authz := cloudauth.NewLDAPAuthorizer(map[string][]string{
		"ops": {"proj-a"},
	})
	srv := New(&fakeStore{}, authz, 0)

	token := mintTestJWTForCloud(t, jwt.MapClaims{"groups": []string{"ops"}})
	req := httptest.NewRequest(http.MethodGet, "/sync/pull?project=other-proj", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unmapped project, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestLDAPModeRejectsTokenWithoutGroups(t *testing.T) {
	authz := cloudauth.NewLDAPAuthorizer(map[string][]string{
		"ops": {"proj-a"},
	})
	srv := New(&fakeStore{}, authz, 0)

	token := mintTestJWTForCloud(t, jwt.MapClaims{"sub": "alice"})
	req := httptest.NewRequest(http.MethodGet, "/sync/pull?project=proj-a", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for token without groups, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestLDAPModeRejectsMalformedJWT(t *testing.T) {
	authz := cloudauth.NewLDAPAuthorizer(map[string][]string{
		"ops": {"proj-a"},
	})
	srv := New(&fakeStore{}, authz, 0)

	req := httptest.NewRequest(http.MethodGet, "/sync/pull?project=proj-a", nil)
	req.Header.Set("Authorization", "Bearer not.a.real.jwt")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for malformed jwt, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestLDAPModeWildcardClaimAuthorizesAnyProject(t *testing.T) {
	authz := cloudauth.NewLDAPAuthorizer(map[string][]string{
		"admins": {cloudauth.WildcardProject},
	})
	srv := New(&fakeStore{}, authz, 0)

	token := mintTestJWTForCloud(t, jwt.MapClaims{"groups": []string{"admins"}})
	for _, project := range []string{"proj-a", "random-proj"} {
		req := httptest.NewRequest(http.MethodGet, "/sync/pull?project="+project, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected wildcard to authorize %q (got %d body=%q)", project, rec.Code, rec.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// 6.5 RED: rate-limiter middleware rejects 2nd call → 429 + Retry-After (REQ-15, REQ-24)
// ---------------------------------------------------------------------------

// countingLimiter allows exactly maxAllowed calls, then denies.
type countingLimiter struct {
	maxAllowed int
	calls      int
}

func (l *countingLimiter) Allow(_ string) bool {
	l.calls++
	return l.calls <= l.maxAllowed
}

func TestWithLDAPLoginFunc_RateLimitMiddleware(t *testing.T) {
	loginCallCount := 0
	loginFn := func(_ context.Context, _, _ string) (string, cloudauth.UserInfo, error) {
		loginCallCount++
		expUnix := time.Now().Add(3600 * time.Second).Unix()
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "alice",
			"exp": float64(expUnix),
		})
		signed, _ := tok.SignedString([]byte("test-key-decoded-only-by-engram"))
		return signed, cloudauth.UserInfo{CN: "Alice"}, nil
	}

	limiter := &countingLimiter{maxAllowed: 1} // allow 1st call, deny 2nd

	realCodec, err := cloudauth.NewLDAPSessionCodec("test-ldap-secret-for-cs")
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec: %v", err)
	}

	srv := New(&fakeStore{}, fakeAuth{}, 0,
		WithLDAPSessionCodec(realCodec),
		WithLDAPLoginFunc(loginFn),
		WithLDAPLimiter(limiter),
	)

	postLogin := func() *httptest.ResponseRecorder {
		form := url.Values{}
		form.Set("username", "alice")
		form.Set("password", "s3cret")
		req := httptest.NewRequest(http.MethodPost, "/dashboard/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// 1st call: allowed (limiter.Allow returns true).
	rec1 := postLogin()
	if rec1.Code == http.StatusTooManyRequests {
		t.Fatalf("expected 1st call to succeed, got 429")
	}

	// 2nd call: rate-limited → 429.
	rec2 := postLogin()
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 2nd call, got %d body=%q", rec2.Code, rec2.Body.String())
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on 429, got none")
	}

	// LDAPLogin callback must NOT have been invoked on the 2nd call.
	// After 1st call loginCallCount == 1 (first succeeded). After 2nd call it
	// must still be 1 if rate limiting blocked before calling the login fn.
	if loginCallCount != 1 {
		t.Fatalf("expected LDAPLogin called exactly once (blocked on 2nd), got %d", loginCallCount)
	}
}
