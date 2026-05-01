package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Gentleman-Programming/engram/internal/store"
	"golang.org/x/term"
)

// runLDAPLogin POSTs the credentials to the upstream login URL and persists
// the returned JWT to cloud.json:Token. The function is the testable core of
// `engram cloud login --ldap`; the interactive prompt lives in cmdCloudLogin.
//
// Contract with the 3rd-party auth service (confirmed):
//   - request:  {"username":"...","password":"..."}
//   - success:  {"status":"Login successful","token":"<jwt>"} (2xx)
//   - failure:  {"error":"..."} with non-2xx status
func runLDAPLogin(cfg store.Config, loginURL, username, password string) error {
	body, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("contact auth service: %w", err)
	}
	defer resp.Body.Close()

	respBody := &bytes.Buffer{}
	if _, err := respBody.ReadFrom(resp.Body); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errPayload struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody.Bytes(), &errPayload)
		message := strings.TrimSpace(errPayload.Error)
		if message == "" {
			message = strings.TrimSpace(respBody.String())
		}
		if message == "" {
			message = resp.Status
		}
		return fmt.Errorf("authentication failed: %s", message)
	}

	var success struct {
		Status string `json:"status"`
		Token  string `json:"token"`
	}
	if err := json.Unmarshal(respBody.Bytes(), &success); err != nil {
		return fmt.Errorf("parse auth response: %w", err)
	}
	token := strings.TrimSpace(success.Token)
	if token == "" {
		return fmt.Errorf("auth response missing token field")
	}

	cc := &cloudConfig{ServerURL: loginURL, Token: token}
	if err := saveCloudConfig(cfg, cc); err != nil {
		return fmt.Errorf("persist cloud config: %w", err)
	}
	return nil
}

// cmdCloudLogin handles `engram cloud login --ldap [--server <url>]`. It
// prompts the user for credentials interactively (password without echo) and
// delegates the actual HTTP + persistence to runLDAPLogin.
func cmdCloudLogin(cfg store.Config) {
	args := os.Args[3:]
	mode := ""
	serverURL := ""
	for i := 0; i < len(args); i++ {
		switch strings.TrimSpace(args[i]) {
		case "--ldap":
			mode = "ldap"
		case "--server":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --server requires a URL argument")
				exitFunc(1)
				return
			}
			serverURL = strings.TrimSpace(args[i+1])
			i++
		case "--help", "-h", "help":
			fmt.Println("usage: engram cloud login --ldap [--server <url>]")
			fmt.Println("Interactive login that exchanges LDAP credentials for a JWT via the cloud server.")
			return
		}
	}
	if mode != "ldap" {
		fmt.Fprintln(os.Stderr, "usage: engram cloud login --ldap [--server <url>]")
		exitFunc(1)
		return
	}
	if serverURL == "" {
		// Fall back to whatever `engram cloud config` previously set.
		existing, err := loadCloudConfig(cfg)
		if err != nil {
			fatal(err)
			return
		}
		if existing != nil {
			serverURL = strings.TrimSpace(existing.ServerURL)
		}
	}
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "error: --server is required (or run `engram cloud config --server <url>` first)")
		exitFunc(1)
		return
	}

	loginURL := strings.TrimRight(serverURL, "/") + "/auth/ldap/login"

	username, err := promptUsername()
	if err != nil {
		fatal(err)
		return
	}
	password, err := promptPassword()
	if err != nil {
		fatal(err)
		return
	}

	if err := runLDAPLogin(cfg, loginURL, username, password); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		exitFunc(1)
		return
	}
	fmt.Println("✓ Login successful, token stored")
}

func promptUsername() (string, error) {
	fmt.Fprint(os.Stdout, "Username: ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("no username provided")
	}
	username := strings.TrimSpace(scanner.Text())
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	return username, nil
}

func promptPassword() (string, error) {
	fmt.Fprint(os.Stdout, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stdout)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(pw), nil
}
