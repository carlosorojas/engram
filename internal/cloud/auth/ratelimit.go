package auth

import (
	"os"
	"strconv"
	"sync"
	"time"
)

// Limiter decides whether an action identified by key should be allowed.
type Limiter interface {
	Allow(key string) bool
}

// SlidingWindowLimiter is a per-key sliding-window rate limiter that tracks
// event timestamps within the configured window duration.
//
// NOTE: This is designed to run as a single in-process instance. It does NOT
// synchronise state across multiple processes or servers — each instance
// maintains its own independent event history. If you run multiple dashboard
// replicas, each replica enforces the limit independently, which means the
// effective cluster-wide limit is max × replica-count.
type SlidingWindowLimiter struct {
	max    int
	window time.Duration
	now    func() time.Time
	mu     sync.Mutex
	events map[string][]time.Time
}

// NewSlidingWindowLimiter creates a SlidingWindowLimiter that allows at most
// max events per window duration for each distinct key.
//
// If now is nil, time.Now is used (production default). Pass a synthetic clock
// in tests to control time without sleeping.
func NewSlidingWindowLimiter(max int, window time.Duration, now func() time.Time) *SlidingWindowLimiter {
	if now == nil {
		now = time.Now
	}
	return &SlidingWindowLimiter{
		max:    max,
		window: window,
		now:    now,
		events: make(map[string][]time.Time),
	}
}

// Allow reports whether the caller identified by key is within the rate limit.
// It records the event if allowed and prunes expired events on every call.
func (l *SlidingWindowLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-l.window)

	// Prune events that have fallen outside the current window.
	existing := l.events[key]
	valid := existing[:0]
	for _, t := range existing {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) < l.max {
		l.events[key] = append(valid, now)
		return true
	}

	// Store the pruned slice (without the new event) to avoid unbounded growth.
	l.events[key] = valid
	return false
}

// DefaultLimiterFromEnv constructs a SlidingWindowLimiter from environment
// variables, falling back to safe defaults when variables are absent or
// unparseable.
//
//   - ENGRAM_LDAP_LOGIN_RATE_LIMIT         — max events per window (default: 10)
//   - ENGRAM_LDAP_LOGIN_RATE_WINDOW_SECONDS — window length in seconds (default: 60)
func DefaultLimiterFromEnv() *SlidingWindowLimiter {
	const (
		defaultMax     = 10
		defaultSeconds = 60
	)

	max := defaultMax
	if v := os.Getenv("ENGRAM_LDAP_LOGIN_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			max = n
		}
	}

	seconds := defaultSeconds
	if v := os.Getenv("ENGRAM_LDAP_LOGIN_RATE_WINDOW_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			seconds = n
		}
	}

	return NewSlidingWindowLimiter(max, time.Duration(seconds)*time.Second, nil)
}
