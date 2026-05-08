package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- helpers ---

// newTestCodec creates an LDAPSessionCodec with a valid 16-byte secret and an
// injected clock, allowing deterministic time in tests.
func newTestCodec(t *testing.T, now func() time.Time) *LDAPSessionCodec {
	t.Helper()
	c, err := NewLDAPSessionCodec("exactly-16bytes!")
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec: %v", err)
	}
	if now != nil {
		c.now = now
	}
	return c
}

// mintFutureJWT mints a JWT whose exp is `offset` from `base`.
func mintFutureJWT(t *testing.T, base time.Time, offset time.Duration) string {
	t.Helper()
	exp := base.Add(offset).Unix()
	return mintTestJWT(t, jwt.MapClaims{
		"sub": "testuser",
		"exp": float64(exp),
	})
}

// sampleUser returns a filled-in UserInfo for round-trip tests.
func sampleUser() UserInfo {
	return UserInfo{
		UID:       "jdoe",
		CN:        "Jane Doe",
		Mail:      "jdoe@example.com",
		GivenName: "Jane",
		SN:        "Doe",
	}
}

// --- 4.1 RoundTrip ---

// TestLDAPSessionCodec_RoundTrip: Mint then Parse → identical jwt + UserInfo.
func TestLDAPSessionCodec_RoundTrip(t *testing.T) {
	fixedNow := time.Unix(1_000_000, 0)
	now := func() time.Time { return fixedNow }
	c := newTestCodec(t, now)

	rawJWT := mintFutureJWT(t, fixedNow, 3600*time.Second)
	user := sampleUser()

	token, err := c.MintDashboardSession(rawJWT, user)
	if err != nil {
		t.Fatalf("MintDashboardSession: %v", err)
	}

	gotJWT, gotUser, err := c.ParseDashboardSession(token)
	if err != nil {
		t.Fatalf("ParseDashboardSession: %v", err)
	}
	if gotJWT != rawJWT {
		t.Errorf("jwt mismatch: want %q, got %q", rawJWT, gotJWT)
	}
	if gotUser != user {
		t.Errorf("user mismatch: want %+v, got %+v", user, gotUser)
	}
}

// --- 4.2 TamperDetection ---

// TestLDAPSessionCodec_TamperDetection: flip one byte after Mint → Parse error.
func TestLDAPSessionCodec_TamperDetection(t *testing.T) {
	fixedNow := time.Unix(1_000_000, 0)
	now := func() time.Time { return fixedNow }
	c := newTestCodec(t, now)

	rawJWT := mintFutureJWT(t, fixedNow, 3600*time.Second)
	token, err := c.MintDashboardSession(rawJWT, sampleUser())
	if err != nil {
		t.Fatalf("MintDashboardSession: %v", err)
	}

	// Flip the first byte of the token.
	bs := []byte(token)
	bs[0] ^= 0x01
	tampered := string(bs)

	_, _, err = c.ParseDashboardSession(tampered)
	if err == nil {
		t.Fatal("want error for tampered token, got nil")
	}
}

// --- 4.3 WrongSecret ---

// TestLDAPSessionCodec_WrongSecret: Mint with secret A, Parse with secret B → error.
func TestLDAPSessionCodec_WrongSecret(t *testing.T) {
	fixedNow := time.Unix(1_000_000, 0)
	now := func() time.Time { return fixedNow }

	cA, err := NewLDAPSessionCodec("secret-A-16bytes")
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec A: %v", err)
	}
	cA.now = now

	cB, err := NewLDAPSessionCodec("secret-B-16bytes")
	if err != nil {
		t.Fatalf("NewLDAPSessionCodec B: %v", err)
	}
	cB.now = now

	rawJWT := mintFutureJWT(t, fixedNow, 3600*time.Second)
	token, err := cA.MintDashboardSession(rawJWT, sampleUser())
	if err != nil {
		t.Fatalf("MintDashboardSession: %v", err)
	}

	_, _, err = cB.ParseDashboardSession(token)
	if err == nil {
		t.Fatal("want error when parsing with wrong secret, got nil")
	}
}

// --- 4.4 MalformedInput ---

// TestLDAPSessionCodec_MalformedInput: "notbase64!!!" → error, no panic.
func TestLDAPSessionCodec_MalformedInput(t *testing.T) {
	c := newTestCodec(t, nil)

	_, _, err := c.ParseDashboardSession("notbase64!!!")
	if err == nil {
		t.Fatal("want error for malformed input, got nil")
	}
}

// --- 4.5 SecretTooShort ---

// TestLDAPSessionCodec_SecretTooShort: NewLDAPSessionCodec("short") → ErrLDAPSecretTooShort.
func TestLDAPSessionCodec_SecretTooShort(t *testing.T) {
	_, err := NewLDAPSessionCodec("short")
	if !errors.Is(err, ErrLDAPSecretTooShort) {
		t.Errorf("want ErrLDAPSecretTooShort, got %v", err)
	}
}

// --- 4.6 MissingExpInJWT ---

// TestLDAPSessionCodec_MissingExpInJWT: Mint with exp-less JWT → ErrJWTMissingExp.
func TestLDAPSessionCodec_MissingExpInJWT(t *testing.T) {
	c := newTestCodec(t, nil)

	rawJWT := mintTestJWT(t, jwt.MapClaims{"sub": "user1"}) // no exp
	_, err := c.MintDashboardSession(rawJWT, sampleUser())
	if !errors.Is(err, ErrJWTMissingExp) {
		t.Errorf("want ErrJWTMissingExp, got %v", err)
	}
}

// --- 4.7 ExpiredJWT ---

// TestLDAPSessionCodec_ExpiredJWT: Mint with exp 31s in past → ErrJWTExpired.
func TestLDAPSessionCodec_ExpiredJWT(t *testing.T) {
	fixedNow := time.Unix(1_000_000, 0)
	now := func() time.Time { return fixedNow }
	c := newTestCodec(t, now)

	// exp = fixedNow - 31s → outside 30s leeway → ErrJWTExpired
	rawJWT := mintFutureJWT(t, fixedNow, -31*time.Second)
	_, err := c.MintDashboardSession(rawJWT, sampleUser())
	if !errors.Is(err, ErrJWTExpired) {
		t.Errorf("want ErrJWTExpired, got %v", err)
	}
}

// --- 4.8 LeewayBoundary ---

// TestLDAPSessionCodec_LeewayBoundary: Mint with exp 29s in past → success (30s leeway).
func TestLDAPSessionCodec_LeewayBoundary(t *testing.T) {
	fixedNow := time.Unix(1_000_000, 0)
	now := func() time.Time { return fixedNow }
	c := newTestCodec(t, now)

	// exp = fixedNow - 29s → within 30s leeway → allowed
	rawJWT := mintFutureJWT(t, fixedNow, -29*time.Second)
	token, err := c.MintDashboardSession(rawJWT, sampleUser())
	if err != nil {
		t.Errorf("want nil error within 30s leeway, got %v", err)
	}
	if token == "" {
		t.Error("want non-empty token")
	}
}

// --- bonus: ensure no dot in encoded part breaks split logic ---

// TestLDAPSessionCodec_ParseMissingDot: token with no dot → error, no panic.
func TestLDAPSessionCodec_ParseMissingDot(t *testing.T) {
	c := newTestCodec(t, nil)
	_, _, err := c.ParseDashboardSession("nodotinhere")
	if err == nil {
		t.Fatal("want error for token with no dot, got nil")
	}
}

// TestLDAPSessionCodec_ParseExtraDots: split on LAST dot, so extra dots in
// payload should still parse (tamper check will reject bad sig, not split).
func TestLDAPSessionCodec_ParseExtraDots(t *testing.T) {
	c := newTestCodec(t, nil)
	// A string with dots but invalid sig — should fail on HMAC, not split.
	_, _, err := c.ParseDashboardSession("a.b.c")
	if err == nil {
		t.Fatal("want error (bad sig), got nil")
	}
	if strings.Contains(err.Error(), "split") {
		t.Errorf("unexpected split error: %v", err)
	}
}
