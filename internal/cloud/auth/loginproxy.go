package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
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
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.UpstreamURL, r.Body)
	if err != nil {
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
		// Distinguish timeout (our deadline elapsed) from connect/transport errors.
		if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
			http.Error(w, "upstream auth service timeout", http.StatusGatewayTimeout)
			return
		}
		http.Error(w, "upstream auth service unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func isTimeoutError(err error) bool {
	type timeout interface{ Timeout() bool }
	var t timeout
	if errors.As(err, &t) {
		return t.Timeout()
	}
	return false
}
