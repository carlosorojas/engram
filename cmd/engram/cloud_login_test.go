package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/internal/store"
)

func newTestCfgWithDataDir(t *testing.T) store.Config {
	t.Helper()
	return store.Config{DataDir: t.TempDir()}
}

func TestRunLDAPLoginPersistsToken(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(body, &creds); err != nil {
			t.Errorf("upstream got non-json body: %s", body)
		}
		if creds.Username != "alice" || creds.Password != "s3cret" {
			t.Errorf("upstream got wrong creds: %+v", creds)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"Login successful","token":"eyJabc123"}`))
	}))
	defer upstream.Close()

	cfg := newTestCfgWithDataDir(t)

	if err := runLDAPLogin(cfg, upstream.URL, "alice", "s3cret"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	// Verify cloud.json contains the token from the upstream response.
	stored, err := os.ReadFile(filepath.Join(cfg.DataDir, "cloud.json"))
	if err != nil {
		t.Fatalf("expected cloud.json written: %v", err)
	}
	var cc cloudConfig
	if err := json.Unmarshal(stored, &cc); err != nil {
		t.Fatalf("parse cloud.json: %v", err)
	}
	if cc.Token != "eyJabc123" {
		t.Fatalf("expected token persisted as eyJabc123, got %q", cc.Token)
	}
	if cc.ServerURL != upstream.URL {
		t.Fatalf("expected ServerURL persisted, got %q", cc.ServerURL)
	}
}

func TestRunLDAPLoginUpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Invalid credentials"}`))
	}))
	defer upstream.Close()

	cfg := newTestCfgWithDataDir(t)

	err := runLDAPLogin(cfg, upstream.URL, "alice", "wrong")
	if err == nil {
		t.Fatal("expected error on upstream 401")
	}
	if !strings.Contains(err.Error(), "Invalid credentials") {
		t.Fatalf("expected error to surface upstream message, got %q", err.Error())
	}
	// No file should be written on error.
	if _, statErr := os.Stat(filepath.Join(cfg.DataDir, "cloud.json")); !os.IsNotExist(statErr) {
		t.Fatalf("expected cloud.json NOT written on error, stat: %v", statErr)
	}
}

func TestRunLDAPLoginConnectionRefused(t *testing.T) {
	cfg := newTestCfgWithDataDir(t)
	err := runLDAPLogin(cfg, "http://127.0.0.1:1", "alice", "x")
	if err == nil {
		t.Fatal("expected error on connection refused")
	}
}

func TestRunLDAPLoginMissingTokenInResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"OK but no token field"}`))
	}))
	defer upstream.Close()

	cfg := newTestCfgWithDataDir(t)
	err := runLDAPLogin(cfg, upstream.URL, "alice", "s3cret")
	if err == nil {
		t.Fatal("expected error when response lacks token field")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected error to mention missing token, got %q", err.Error())
	}
}
