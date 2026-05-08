package cloudserver

import (
	"context"
	"fmt"
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

// ---------------------------------------------------------------------------
// Phase 9: LDAP group-based admin authorization (REQ-LDAP-ADMIN-*)
// ---------------------------------------------------------------------------

// mintLDAPSessionCookieForGroups mints an LDAP dashboard session cookie
// containing a JWT with the given groups claim, using the provided codec.
func mintLDAPSessionCookieForGroups(t *testing.T, codec *cloudauth.LDAPSessionCodec, groups []string) *http.Cookie {
	t.Helper()
	groupsIface := make([]interface{}, len(groups))
	for i, g := range groups {
		groupsIface[i] = g
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    "alice",
		"groups": groupsIface,
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	})
	signed, err := tok.SignedString([]byte("test-key-for-ldap-admin"))
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	sessionToken, err := codec.MintDashboardSession(signed, cloudauth.UserInfo{CN: "Alice"})
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	return &http.Cookie{Name: dashboardSessionCookieName, Value: sessionToken}
}

// 9.1 RED: WithLDAPAdminGroups option exists and sets the field.
func TestWithLDAPAdminGroups_OptionWires(t *testing.T) {
	srv := New(&fakeStore{}, fakeAuth{}, 0,
		WithLDAPAdminGroups([]string{"ops-admins"}),
	)
	if len(srv.ldapAdminGroups) != 1 || srv.ldapAdminGroups[0] != "ops-admins" {
		t.Fatalf("expected ldapAdminGroups=[ops-admins], got %v", srv.ldapAdminGroups)
	}
}

// 9.2 RED: isDashboardAdmin returns true when LDAP session cookie contains an admin group.
func TestIsDashboardAdmin_LDAPAdminGroupMatch(t *testing.T) {
	codec, err := cloudauth.NewLDAPSessionCodec("test-ldap-secret-p9")
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec: %v", err)
	}
	ldapAuth := cloudauth.NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	srv := New(&fakeStore{}, ldapAuth, 0,
		WithLDAPSessionCodec(codec),
		WithLDAPAdminGroups([]string{"ops-admins"}),
	)

	cookie := mintLDAPSessionCookieForGroups(t, codec, []string{"ops", "ops-admins"})
	req := httptest.NewRequest(http.MethodGet, "/dashboard/admin", nil)
	req.AddCookie(cookie)

	if !srv.isDashboardAdmin(req) {
		t.Fatal("expected isDashboardAdmin=true when JWT groups contains admin group")
	}
}

// 9.3 RED: isDashboardAdmin returns false when JWT groups have no overlap with admin groups.
func TestIsDashboardAdmin_LDAPNoGroupOverlap(t *testing.T) {
	codec, err := cloudauth.NewLDAPSessionCodec("test-ldap-secret-p9")
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec: %v", err)
	}
	ldapAuth := cloudauth.NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	srv := New(&fakeStore{}, ldapAuth, 0,
		WithLDAPSessionCodec(codec),
		WithLDAPAdminGroups([]string{"ops-admins"}),
	)

	cookie := mintLDAPSessionCookieForGroups(t, codec, []string{"devs", "qa"})
	req := httptest.NewRequest(http.MethodGet, "/dashboard/admin", nil)
	req.AddCookie(cookie)

	if srv.isDashboardAdmin(req) {
		t.Fatal("expected isDashboardAdmin=false when JWT groups have no overlap")
	}
}

// 9.4 RED: isDashboardAdmin returns false when no cookie is present in LDAP mode.
func TestIsDashboardAdmin_LDAPNoCookie(t *testing.T) {
	codec, err := cloudauth.NewLDAPSessionCodec("test-ldap-secret-p9")
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec: %v", err)
	}
	ldapAuth := cloudauth.NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	srv := New(&fakeStore{}, ldapAuth, 0,
		WithLDAPSessionCodec(codec),
		WithLDAPAdminGroups([]string{"ops-admins"}),
	)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/admin", nil)
	if srv.isDashboardAdmin(req) {
		t.Fatal("expected isDashboardAdmin=false when no cookie present")
	}
}

// 9.5 RED: token-mode static admin token still works when LDAP admin groups are also set.
func TestIsDashboardAdmin_TokenModeStillWorksAlongsideLDAPGroups(t *testing.T) {
	authSvc, err := cloudauth.NewService(nil, strings.Repeat("x", 32))
	if err != nil {
		t.Fatalf("new auth service: %v", err)
	}
	authSvc.SetBearerToken("sync-token")
	authSvc.SetDashboardSessionTokens([]string{"admin-token"})

	srv := New(&fakeStore{}, authSvc, 0,
		WithDashboardAdminToken("admin-token"),
		WithLDAPAdminGroups([]string{"ops-admins"}),
	)

	// Log in with the token-mode admin token
	login := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/dashboard/login", strings.NewReader("token=admin-token"))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Handler().ServeHTTP(login, loginReq)
	if login.Code != http.StatusSeeOther {
		t.Fatalf("expected login redirect, got %d body=%q", login.Code, login.Body.String())
	}

	// Confirm admin page is accessible via the cookie
	admin := httptest.NewRecorder()
	adminReq := httptest.NewRequest(http.MethodGet, "/dashboard/admin", nil)
	for _, c := range login.Result().Cookies() {
		adminReq.AddCookie(c)
	}
	srv.Handler().ServeHTTP(admin, adminReq)
	if admin.Code != http.StatusOK {
		t.Fatalf("expected token-mode admin still accessible when LDAPAdminGroups is also set, got %d body=%q", admin.Code, admin.Body.String())
	}
}

// 9.6 RED: HTTP-level — admin page accessible with admin-group JWT session.
func TestLDAPAdminGroups_AdminPageAccessible(t *testing.T) {
	codec, err := cloudauth.NewLDAPSessionCodec("test-ldap-secret-p9")
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec: %v", err)
	}
	ldapAuth := cloudauth.NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	srv := New(&fakeStore{}, ldapAuth, 0,
		WithLDAPSessionCodec(codec),
		WithLDAPAdminGroups([]string{"ops-admins"}),
	)

	cookie := mintLDAPSessionCookieForGroups(t, codec, []string{"ops", "ops-admins"})

	// Dashboard session authorization also runs via authorizeDashboardRequest,
	// which in LDAP mode calls s.ldapCodec.ParseDashboardSession. We need a
	// request with the same cookie for both the session guard and the admin check.
	admin := httptest.NewRecorder()
	adminReq := httptest.NewRequest(http.MethodGet, "/dashboard/admin", nil)
	adminReq.AddCookie(cookie)
	srv.Handler().ServeHTTP(admin, adminReq)
	if admin.Code != http.StatusOK {
		t.Fatalf("expected admin page 200 with admin-group LDAP session, got %d body=%q", admin.Code, admin.Body.String())
	}
	if !strings.Contains(admin.Body.String(), "ADMIN SURFACE") {
		t.Fatalf("expected admin page content, got body=%q", admin.Body.String())
	}
}

// 9.7 RED: HTTP-level — admin page forbidden for non-admin-group JWT session.
func TestLDAPAdminGroups_AdminPageForbiddenForNonAdmin(t *testing.T) {
	codec, err := cloudauth.NewLDAPSessionCodec("test-ldap-secret-p9")
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec: %v", err)
	}
	ldapAuth := cloudauth.NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	srv := New(&fakeStore{}, ldapAuth, 0,
		WithLDAPSessionCodec(codec),
		WithLDAPAdminGroups([]string{"ops-admins"}),
	)

	// devs can log in to dashboard but are not in ops-admins
	cookie := mintLDAPSessionCookieForGroups(t, codec, []string{"ops"})

	admin := httptest.NewRecorder()
	adminReq := httptest.NewRequest(http.MethodGet, "/dashboard/admin", nil)
	adminReq.AddCookie(cookie)
	srv.Handler().ServeHTTP(admin, adminReq)
	if admin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin-group LDAP session, got %d body=%q", admin.Code, admin.Body.String())
	}
}

// Ensure fmt import is used (compile guard).
var _ = fmt.Sprintf
