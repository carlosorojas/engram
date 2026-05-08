package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// LoginProxy forwards client login requests to an upstream LDAP auth service
// and returns the upstream response verbatim. The cloud server does not
// inspect, modify, or persist credentials — it only relays. When APIKey is
// non-empty, it is attached as the `x-api-key` header on every upstream
// request: this is a server-to-upstream shared secret, intentionally NOT
// exposed to clients.
type LoginProxy struct {
	UpstreamURL string
	Client      *http.Client
	APIKey      string
}

// NewLoginProxy returns a LoginProxy with an http.Client whose Timeout is the
// provided duration. Set APIKey on the returned value if the upstream service
// requires an x-api-key header.
func NewLoginProxy(upstreamURL string, timeout time.Duration) *LoginProxy {
	return &LoginProxy{
		UpstreamURL: upstreamURL,
		Client:      &http.Client{Timeout: timeout},
	}
}

func (p *LoginProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[engram-cloud][loginproxy] %s %s -> upstream=%s api_key_set=%t", r.Method, r.URL.Path, p.UpstreamURL, p.APIKey != "")

	bodyBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		log.Printf("[engram-cloud][loginproxy] read request body failed: %v", readErr)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	logRequestPayload(bodyBytes)

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.UpstreamURL, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("[engram-cloud][loginproxy] build upstream request failed: %v", err)
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		upstreamReq.Header.Set("Content-Type", ct)
	} else {
		upstreamReq.Header.Set("Content-Type", "application/json")
	}
	if p.APIKey != "" {
		upstreamReq.Header.Set("x-api-key", p.APIKey)
	}

	resp, err := p.Client.Do(upstreamReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
			log.Printf("[engram-cloud][loginproxy] upstream timeout: %v", err)
			http.Error(w, "upstream auth service timeout", http.StatusGatewayTimeout)
			return
		}
		log.Printf("[engram-cloud][loginproxy] upstream unreachable: %v", err)
		http.Error(w, "upstream auth service unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[engram-cloud][loginproxy] upstream responded status=%d body_len=%d", resp.StatusCode, len(respBody))
	} else {
		log.Printf("[engram-cloud][loginproxy] upstream responded status=%d body=%s", resp.StatusCode, truncate(respBody, 512))
	}

	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// upstreamLoginResponse is the internal struct used to parse the JSON body
// returned by the upstream auth service on a successful login.
type upstreamLoginResponse struct {
	Status string   `json:"status"`
	Token  string   `json:"token"`
	User   UserInfo `json:"user"` // optional: some upstreams return user at top level; the JWT user claim is the source of truth.
}

// userInfoFromJWT decodes the JWT (unverified — same posture as LDAPAuthorizer)
// and extracts the `user` claim as a UserInfo struct. Returns a zero-value
// UserInfo (no error) when the JWT cannot be parsed or the claim is absent —
// the caller can fall back to whatever data lived in the response body.
func userInfoFromJWT(rawJWT string) UserInfo {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(rawJWT, &claims); err != nil {
		return UserInfo{}
	}
	rawUser, ok := claims["user"].(map[string]any)
	if !ok {
		return UserInfo{}
	}
	getStr := func(key string) string {
		if v, ok := rawUser[key].(string); ok {
			return v
		}
		return ""
	}
	return UserInfo{
		UID:       getStr("uid"),
		CN:        getStr("cn"),
		Mail:      getStr("mail"),
		GivenName: getStr("givenName"),
		SN:        getStr("sn"),
	}
}

// Login authenticates username/password against the upstream auth service and
// returns the raw JWT string plus the UserInfo fields embedded in the upstream
// response. It does NOT go through ServeHTTP — it is a direct programmatic
// call for use by the dashboard login handler.
//
// On non-2xx status → error containing the status code.
// On 2xx with empty token → error "empty token in upstream response".
// On 2xx with no "user" key → returns (token, zero-value UserInfo, nil).
// On timeout → error wrapping context.DeadlineExceeded (or isTimeoutError).
//
// Password and full token are never logged.
func (p *LoginProxy) Login(ctx context.Context, username, password string) (string, UserInfo, error) {
	log.Printf("[engram-cloud][loginproxy] Login username=%q -> upstream=%s api_key_set=%t", username, p.UpstreamURL, p.APIKey != "")

	payload, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return "", UserInfo{}, fmt.Errorf("loginproxy: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.UpstreamURL, bytes.NewReader(payload))
	if err != nil {
		return "", UserInfo{}, fmt.Errorf("loginproxy: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		req.Header.Set("x-api-key", p.APIKey)
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
			log.Printf("[engram-cloud][loginproxy] Login timeout: %v", err)
			return "", UserInfo{}, fmt.Errorf("loginproxy: upstream timeout: %w", err)
		}
		log.Printf("[engram-cloud][loginproxy] Login upstream unreachable: %v", err)
		return "", UserInfo{}, fmt.Errorf("loginproxy: upstream unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[engram-cloud][loginproxy] Login upstream status=%d body=%s", resp.StatusCode, truncate(body, 512))
		return "", UserInfo{}, fmt.Errorf("loginproxy: upstream returned status %d", resp.StatusCode)
	}

	log.Printf("[engram-cloud][loginproxy] Login upstream status=%d body_len=%d body=%s", resp.StatusCode, len(body), truncate(body, 1024))

	var parsed upstreamLoginResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", UserInfo{}, fmt.Errorf("loginproxy: unmarshal upstream response: %w", err)
	}
	if parsed.Token == "" {
		return "", UserInfo{}, fmt.Errorf("loginproxy: empty token in upstream response")
	}

	// User info is sourced from the JWT claims (the upstream embeds it there).
	// Fall back to the top-level response `user` field if the JWT lacks it.
	info := userInfoFromJWT(parsed.Token)
	if info == (UserInfo{}) {
		info = parsed.User
	}
	log.Printf("[engram-cloud][loginproxy] Login parsed: token_len=%d user.uid=%q user.cn=%q user.mail=%q", len(parsed.Token), info.UID, info.CN, info.Mail)

	return parsed.Token, info, nil
}

// logRequestPayload logs the JSON keys and the username, but NEVER the
// password itself — only its length, so we can confirm it was non-empty.
func logRequestPayload(body []byte) {
	if len(body) == 0 {
		log.Printf("[engram-cloud][loginproxy] request payload: empty body")
		return
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		log.Printf("[engram-cloud][loginproxy] request payload: non-JSON, len=%d", len(body))
		return
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	username, _ := raw["username"].(string)
	pw, _ := raw["password"].(string)
	log.Printf("[engram-cloud][loginproxy] request payload: keys=%v username=%q password_len=%d", keys, username, len(pw))
}

func truncate(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}

func isTimeoutError(err error) bool {
	type timeout interface{ Timeout() bool }
	var t timeout
	if errors.As(err, &t) {
		return t.Timeout()
	}
	return false
}
