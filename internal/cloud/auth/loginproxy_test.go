package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginProxyForwardsSuccessVerbatim(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"username":"alice"`) {
			t.Errorf("upstream did not receive request body, got %q", body)
		}
		if r.Header.Get("Content-Type") == "" {
			t.Errorf("expected Content-Type header to be forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"Login successful","token":"eyJabc"}`))
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 10*time.Second)
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(`{"username":"alice","password":"s3cret"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"token":"eyJabc"`) {
		t.Fatalf("expected upstream body verbatim, got %q", rec.Body.String())
	}
}

func TestLoginProxyForwardsUpstreamErrorVerbatim(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Invalid credentials"}`))
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 10*time.Second)
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(`{"username":"x","password":"y"}`))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 passthrough, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"Invalid credentials"`) {
		t.Fatalf("expected upstream error body verbatim, got %q", rec.Body.String())
	}
}

func TestLoginProxyTimeoutReturns504(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 50*time.Millisecond)
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 on timeout, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestLoginProxyConnectionRefusedReturns502(t *testing.T) {
	// Use a port that nothing is listening on. http://127.0.0.1:1 is reliably refused.
	proxy := NewLoginProxy("http://127.0.0.1:1/api/v1/ldap/auth/login", 1*time.Second)
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on connection refused, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestLoginProxyAddsAPIKeyHeader(t *testing.T) {
	receivedKey := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"OK","token":"t"}`))
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 5*time.Second)
	proxy.APIKey = "secret-shared-with-upstream"

	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(`{"username":"a","password":"b"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if receivedKey != "secret-shared-with-upstream" {
		t.Fatalf("expected upstream to receive x-api-key, got %q", receivedKey)
	}
}

func TestLoginProxyOmitsAPIKeyHeaderWhenEmpty(t *testing.T) {
	receivedKey := "PRESENT"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 5*time.Second)
	// APIKey deliberately left empty.

	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if receivedKey != "" {
		t.Fatalf("expected no x-api-key header sent upstream, got %q", receivedKey)
	}
}

// ---------------------------------------------------------------------------
// Login() method tests (Phase 3)
// ---------------------------------------------------------------------------

// 3.1 RED: success path — all UserInfo fields populated, jwt returned.
func TestLoginProxy_Login_Success(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"username":"alice"`) {
			t.Errorf("upstream did not receive username, got %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"status": "ok",
			"token":  "eyJheader.eyJpayload.sig",
			"user": {
				"uid":       "alice",
				"cn":        "Alice Liddell",
				"mail":      "alice@example.com",
				"givenName": "Alice",
				"sn":        "Liddell"
			}
		}`))
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 5*time.Second)
	jwt, info, err := proxy.Login(t.Context(), "alice", "wonderland")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jwt != "eyJheader.eyJpayload.sig" {
		t.Errorf("expected jwt to match, got %q", jwt)
	}
	if info.UID != "alice" {
		t.Errorf("expected UID=alice, got %q", info.UID)
	}
	if info.CN != "Alice Liddell" {
		t.Errorf("expected CN=Alice Liddell, got %q", info.CN)
	}
	if info.Mail != "alice@example.com" {
		t.Errorf("expected Mail=alice@example.com, got %q", info.Mail)
	}
	if info.GivenName != "Alice" {
		t.Errorf("expected GivenName=Alice, got %q", info.GivenName)
	}
	if info.SN != "Liddell" {
		t.Errorf("expected SN=Liddell, got %q", info.SN)
	}
}

// 3.2 RED: upstream returns token="" → error mentions empty token.
func TestLoginProxy_Login_EmptyToken(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","token":""}`))
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 5*time.Second)
	_, _, err := proxy.Login(t.Context(), "alice", "wonderland")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
	if !strings.Contains(err.Error(), "empty token") {
		t.Errorf("error should mention 'empty token', got %q", err.Error())
	}
}

// 3.3 RED: upstream returns no "user" key → jwt OK, zero-value UserInfo, nil error.
func TestLoginProxy_Login_MissingUserObject(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"abc"}`))
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 5*time.Second)
	jwt, info, err := proxy.Login(t.Context(), "alice", "wonderland")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jwt != "abc" {
		t.Errorf("expected jwt=abc, got %q", jwt)
	}
	if info != (UserInfo{}) {
		t.Errorf("expected zero-value UserInfo, got %+v", info)
	}
}

// 3.4 RED: upstream returns 401 → error mentions 401.
func TestLoginProxy_Login_Upstream401(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 5*time.Second)
	_, _, err := proxy.Login(t.Context(), "alice", "badpass")
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status 401, got %q", err.Error())
	}
}

// 3.5 RED: upstream returns 502 → error mentions 502.
func TestLoginProxy_Login_Upstream502(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`bad gateway`))
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 5*time.Second)
	_, _, err := proxy.Login(t.Context(), "alice", "pass")
	if err == nil {
		t.Fatal("expected error for 502, got nil")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should mention status 502, got %q", err.Error())
	}
}

// 3.6 RED: stub delays beyond timeout → error wraps context.DeadlineExceeded or isTimeoutError.
func TestLoginProxy_Login_Timeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewLoginProxy(upstream.URL, 50*time.Millisecond)
	_, _, err := proxy.Login(t.Context(), "alice", "pass")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !isTimeoutError(err) {
		t.Errorf("expected timeout error (DeadlineExceeded or isTimeoutError), got %v", err)
	}
}
