package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signToken mints an RS256 ID-token under kid. Helper for negative-case
// verification tests — we never want to call out to real Google during unit
// tests, so we generate keys locally and seed them into the verifier.
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	out, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return out
}

func newVerifierWithKey(t *testing.T) (*GoogleIDTokenVerifier, *rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	kid := "test-kid"
	v := NewGoogleIDTokenVerifier(nil)
	v.SetKeys(map[string]*rsa.PublicKey{kid: &priv.PublicKey}, time.Now())
	return v, priv, kid
}

func validClaims(audience string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":            "https://accounts.google.com",
		"aud":            audience,
		"sub":            "1234567890",
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice",
		"picture":        "https://example.com/a.png",
		"iat":            now.Unix(),
		"exp":            now.Add(10 * time.Minute).Unix(),
	}
}

func TestVerify_HappyPath(t *testing.T) {
	v, priv, kid := newVerifierWithKey(t)
	tok := signToken(t, priv, kid, validClaims("client-123"))

	claims, err := v.Verify(context.Background(), tok, "client-123")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("email: got %q want %q", claims.Email, "alice@example.com")
	}
	if claims.Audience != "client-123" {
		t.Errorf("audience: got %q want %q", claims.Audience, "client-123")
	}
	if !claims.EmailVerified {
		t.Errorf("email_verified should be true")
	}
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
	v, priv, kid := newVerifierWithKey(t)
	tok := signToken(t, priv, kid, validClaims("other-app"))
	if _, err := v.Verify(context.Background(), tok, "client-123"); err == nil {
		t.Fatal("expected audience mismatch to fail")
	} else if !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected audience error, got %v", err)
	}
}

func TestVerify_RejectsWrongIssuer(t *testing.T) {
	v, priv, kid := newVerifierWithKey(t)
	c := validClaims("client-123")
	c["iss"] = "https://evil.example.com"
	tok := signToken(t, priv, kid, c)
	if _, err := v.Verify(context.Background(), tok, "client-123"); err == nil {
		t.Fatal("expected issuer mismatch to fail")
	}
}

func TestVerify_RejectsUnverifiedEmail(t *testing.T) {
	v, priv, kid := newVerifierWithKey(t)
	c := validClaims("client-123")
	c["email_verified"] = false
	tok := signToken(t, priv, kid, c)
	if _, err := v.Verify(context.Background(), tok, "client-123"); err == nil {
		t.Fatal("expected unverified email to fail")
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	v, priv, kid := newVerifierWithKey(t)
	c := validClaims("client-123")
	// Pull exp 10 minutes into the past, well outside the 60s leeway.
	c["exp"] = time.Now().Add(-10 * time.Minute).Unix()
	c["iat"] = time.Now().Add(-15 * time.Minute).Unix()
	tok := signToken(t, priv, kid, c)
	if _, err := v.Verify(context.Background(), tok, "client-123"); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func TestVerify_RejectsBadSignature(t *testing.T) {
	v, _, kid := newVerifierWithKey(t)
	// Sign with a *different* private key. The cached kid still resolves to
	// the verifier's public key, so the signature must fail to verify.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := signToken(t, otherKey, kid, validClaims("client-123"))
	if _, err := v.Verify(context.Background(), tok, "client-123"); err == nil {
		t.Fatal("expected signature mismatch to fail")
	}
}

func TestVerify_RejectsHS256AlgConfusion(t *testing.T) {
	v, _, _ := newVerifierWithKey(t)
	hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims("client-123"))
	hsTok.Header["kid"] = "test-kid"
	signed, err := hsTok.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("HS256 sign: %v", err)
	}
	if _, err := v.Verify(context.Background(), signed, "client-123"); err == nil {
		t.Fatal("expected HS256 to be rejected (alg confusion guard)")
	}
}

func TestVerify_RejectsUnknownKid(t *testing.T) {
	v, priv, _ := newVerifierWithKey(t)
	// Sign with the right private key but advertise a kid the verifier
	// doesn't know about. Production publicKey() will trigger a JWKS
	// refresh; here we bypass that by clearing the http client to an
	// invalid endpoint so the refresh fails predictably.
	v.JWKSURL = "http://127.0.0.1:1/non-existent"
	tok := signToken(t, priv, "unknown-kid", validClaims("client-123"))
	if _, err := v.Verify(context.Background(), tok, "client-123"); err == nil {
		t.Fatal("expected unknown kid + failed refresh to error")
	}
}

func TestVerify_EmptyArgs(t *testing.T) {
	v := NewGoogleIDTokenVerifier(nil)
	if _, err := v.Verify(context.Background(), "", "client-123"); err == nil {
		t.Fatal("empty id_token should fail")
	}
	if _, err := v.Verify(context.Background(), "abc.def.ghi", ""); err == nil {
		t.Fatal("empty audience should fail")
	}
}

func TestRefreshJWKS_ParsesGoogleStyleResponse(t *testing.T) {
	// Stand up a tiny HTTP server that returns a minimal JWKS so we
	// exercise the wire-format decoder (base64url N/E) without hitting
	// Google. Use SetKeys above for everything else.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use the encoder defined inside the package to keep the test
		// independent of any string manipulation. base64.RawURLEncoding
		// matches what google.golang.org/api/idtoken does.
		out := jwksJSON(t, priv, "k1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}))
	defer srv.Close()

	v := NewGoogleIDTokenVerifier(nil)
	v.JWKSURL = srv.URL
	tok := signToken(t, priv, "k1", validClaims("client-123"))
	claims, err := v.Verify(context.Background(), tok, "client-123")
	if err != nil {
		t.Fatalf("Verify via live JWKS: %v", err)
	}
	if claims.Subject != "1234567890" {
		t.Errorf("subject: got %q want %q", claims.Subject, "1234567890")
	}
}

// jwksJSON marshals priv into a single-key JWKS document.
func jwksJSON(t *testing.T, priv *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	type key struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	type set struct {
		Keys []key `json:"keys"`
	}

	n := priv.PublicKey.N.Bytes()
	e := priv.PublicKey.E
	eBytes := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}

	buf, err := json.Marshal(set{Keys: []key{{
		Kid: kid, Kty: "RSA", Alg: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(n),
		E: base64.RawURLEncoding.EncodeToString(eBytes),
	}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return buf
}
