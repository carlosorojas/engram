package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ErrLDAPSecretTooShort is returned by NewLDAPSessionCodec when the secret is
// shorter than 16 bytes. (Distinct from the package-level ErrSecretTooShort
// which guards the 32-byte JWT signing secret.)
var ErrLDAPSecretTooShort = errors.New("ldap session codec: secret must be at least 16 bytes")

// ldapSessionEnvelope is the JSON payload stored inside the dashboard session
// token. It carries the upstream JWT and the display-information for the user.
type ldapSessionEnvelope struct {
	JWT  string   `json:"jwt"`
	User UserInfo `json:"user"`
}

// LDAPSessionCodec mints and parses HMAC-SHA256-protected dashboard session
// tokens of the form "<base64url(json)>.<base64url(hmac)>".
//
// The envelope is NOT encrypted — it is integrity-protected only. Do not store
// secrets in UserInfo fields.
type LDAPSessionCodec struct {
	secret []byte
	now    func() time.Time
}

// NewLDAPSessionCodec returns a ready-to-use codec.
// Returns ErrSecretTooShort when len(secret) < 16.
func NewLDAPSessionCodec(secret string) (*LDAPSessionCodec, error) {
	if len(secret) < 16 {
		return nil, ErrLDAPSecretTooShort
	}
	return &LDAPSessionCodec{
		secret: []byte(secret),
		now:    time.Now,
	}, nil
}

// MintDashboardSession creates a signed dashboard session token.
//
// It validates the upstream JWT exp via ExtractMaxAge (30 s leeway) and
// propagates ErrJWTMissingExp / ErrJWTExpired on failure.
//
// Token format: base64url(json_envelope) + "." + base64url(hmac_sha256(encoded_envelope))
func (c *LDAPSessionCodec) MintDashboardSession(rawJWT string, info UserInfo) (string, error) {
	// 1. Validate JWT exp.
	if _, err := ExtractMaxAge(rawJWT, c.now); err != nil {
		return "", err
	}

	// 2. Marshal envelope.
	env := ldapSessionEnvelope{JWT: rawJWT, User: info}
	jsonBytes, err := json.Marshal(env)
	if err != nil {
		return "", err
	}

	// 3. Base64-url-encode (no padding).
	enc := base64.RawURLEncoding.EncodeToString(jsonBytes)

	// 4. Compute HMAC-SHA256 over the encoded envelope.
	sig := c.hmacOf(enc)

	// 5. Encode signature.
	encSig := base64.RawURLEncoding.EncodeToString(sig)

	// 6. Return "<encoded>.<sig>".
	return enc + "." + encSig, nil
}

// ParseDashboardSession decodes and validates a token produced by MintDashboardSession.
//
// It re-validates the embedded JWT exp on every parse, ensuring that an expired
// cookie is rejected even if the cookie itself has not been evicted yet.
//
// Returns ErrJWTMissingExp / ErrJWTExpired when the JWT inside the envelope is
// no longer valid.
func (c *LDAPSessionCodec) ParseDashboardSession(token string) (rawJWT string, info UserInfo, err error) {
	// 1. Split on the LAST dot.
	idx := strings.LastIndex(token, ".")
	if idx < 0 {
		return "", UserInfo{}, errors.New("ldap session codec: malformed token (no dot separator)")
	}
	enc := token[:idx]
	encSig := token[idx+1:]

	// 2. Decode signature.
	sig, err := base64.RawURLEncoding.DecodeString(encSig)
	if err != nil {
		return "", UserInfo{}, errors.New("ldap session codec: malformed token (bad signature encoding)")
	}

	// 3. Recompute HMAC and compare.
	expected := c.hmacOf(enc)
	if !hmac.Equal(sig, expected) {
		return "", UserInfo{}, errors.New("ldap session codec: signature mismatch")
	}

	// 4. Decode envelope.
	jsonBytes, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", UserInfo{}, errors.New("ldap session codec: malformed token (bad payload encoding)")
	}
	var env ldapSessionEnvelope
	if err := json.Unmarshal(jsonBytes, &env); err != nil {
		return "", UserInfo{}, err
	}

	// 5. Re-validate JWT exp.
	if _, err := ExtractMaxAge(env.JWT, c.now); err != nil {
		return "", UserInfo{}, err
	}

	return env.JWT, env.User, nil
}

// hmacOf computes HMAC-SHA256 of s using c.secret.
func (c *LDAPSessionCodec) hmacOf(s string) []byte {
	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(s))
	return h.Sum(nil)
}
