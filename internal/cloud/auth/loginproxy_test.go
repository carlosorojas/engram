package auth

import (
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
