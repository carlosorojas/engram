package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSlidingWindowLimiter_UnderLimit verifies that calls 1–9 are all allowed
// when max is 10 (under the limit).
func TestSlidingWindowLimiter_UnderLimit(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	l := NewSlidingWindowLimiter(10, time.Minute, clock)

	for i := 0; i < 9; i++ {
		if !l.Allow("user1") {
			t.Fatalf("call %d: expected Allow=true, got false", i+1)
		}
	}
}

// TestSlidingWindowLimiter_AtLimit verifies the 10th call is allowed but the
// 11th is denied when max is 10.
func TestSlidingWindowLimiter_AtLimit(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	l := NewSlidingWindowLimiter(10, time.Minute, clock)

	for i := 0; i < 10; i++ {
		if !l.Allow("user1") {
			t.Fatalf("call %d: expected Allow=true, got false", i+1)
		}
	}

	if l.Allow("user1") {
		t.Fatal("11th call: expected Allow=false, got true")
	}
}

// TestSlidingWindowLimiter_WindowExpiry verifies that after the window passes
// (via injected clock), a previously-denied key is allowed again.
func TestSlidingWindowLimiter_WindowExpiry(t *testing.T) {
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	l := NewSlidingWindowLimiter(3, time.Minute, clock)

	// Exhaust the limit.
	for i := 0; i < 3; i++ {
		if !l.Allow("user2") {
			t.Fatalf("call %d: expected Allow=true", i+1)
		}
	}
	if l.Allow("user2") {
		t.Fatal("4th call before window expiry: expected false")
	}

	// Advance past the window.
	advanceClock(61 * time.Second)

	// Now the key should be allowed again.
	if !l.Allow("user2") {
		t.Fatal("after window expiry: expected Allow=true")
	}
}

// TestSlidingWindowLimiter_Concurrent verifies that under 50 concurrent
// goroutines, there is no data race and total allowed calls do not exceed max.
func TestSlidingWindowLimiter_Concurrent(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	const max = 10
	l := NewSlidingWindowLimiter(max, time.Minute, clock)

	var wg sync.WaitGroup
	var allowed atomic.Int64

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("concurrent-key") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got > max {
		t.Fatalf("allowed %d calls, expected ≤ %d", got, max)
	}
}

// TestDefaultLimiterFromEnv_Defaults verifies that when no env vars are set,
// the limiter uses 10/60s defaults and denies the 11th call.
func TestDefaultLimiterFromEnv_Defaults(t *testing.T) {
	t.Setenv("ENGRAM_LDAP_LOGIN_RATE_LIMIT", "")
	t.Setenv("ENGRAM_LDAP_LOGIN_RATE_WINDOW_SECONDS", "")

	l := DefaultLimiterFromEnv()

	for i := 0; i < 10; i++ {
		if !l.Allow("env-user") {
			t.Fatalf("call %d: expected Allow=true (default max=10)", i+1)
		}
	}
	if l.Allow("env-user") {
		t.Fatal("11th call: expected Allow=false with default max=10")
	}
}

// TestDefaultLimiterFromEnv_Override verifies that ENGRAM_LDAP_LOGIN_RATE_LIMIT
// and ENGRAM_LDAP_LOGIN_RATE_WINDOW_SECONDS are respected.
func TestDefaultLimiterFromEnv_Override(t *testing.T) {
	t.Setenv("ENGRAM_LDAP_LOGIN_RATE_LIMIT", "3")
	t.Setenv("ENGRAM_LDAP_LOGIN_RATE_WINDOW_SECONDS", "120")

	l := DefaultLimiterFromEnv()

	for i := 0; i < 3; i++ {
		if !l.Allow("override-user") {
			t.Fatalf("call %d: expected Allow=true (max=3)", i+1)
		}
	}
	if l.Allow("override-user") {
		t.Fatal("4th call: expected Allow=false with max=3")
	}
}
