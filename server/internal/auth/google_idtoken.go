// Package auth — Google OIDC ID-token verification.
//
// Google's ID tokens are signed JWTs (RS256). To trust the email / sub
// returned during a sign-in flow we MUST:
//
//  1. fetch Google's current JWKS,
//  2. verify the RS256 signature with the matching public key,
//  3. assert iss is accounts.google.com (or the https variant),
//  4. assert aud equals the OAuth client_id this server is registered as,
//  5. assert exp has not passed (clock-skew tolerated by jwt.WithLeeway),
//  6. assert email_verified is true.
//
// Skipping any of these means an attacker who can get Google to issue an
// id_token for *some other* client can impersonate users of this client
// (confused-deputy / cross-OAuth-app replay). This file implements all of
// them without taking on a Go 1.25-only `google.golang.org/api/idtoken`
// dependency — the module path is incompatible with our toolchain pin.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// googleJWKSURL is the JWKS endpoint advertised by Google's OpenID Connect
// discovery document. Hard-coded because the discovery document itself is
// effectively immutable for this purpose and an extra hop would only widen
// the attack surface (DNS hijack of accounts.google.com discovery → key
// substitution).
const googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// jwksRefreshAfter controls how often we re-pull keys when the cached set
// has not expired yet. Google rotates signing keys every ~10 days; refreshing
// every 6h keeps us comfortably inside that window.
const jwksRefreshAfter = 6 * time.Hour

// jwtLeeway tolerates clock skew between this server and Google. 60s matches
// what google.golang.org/api/idtoken applies internally.
const jwtLeeway = 60 * time.Second

// googleIssuers lists every "iss" claim Google may emit. Token validation
// must accept either form (RFC 8414 §2 calls out the optional scheme).
var googleIssuers = []string{
	"accounts.google.com",
	"https://accounts.google.com",
}

// GoogleIDTokenClaims is the subset of OIDC claims we read after a successful
// verification. Fields beyond these (locale, hd, etc.) are intentionally
// dropped to avoid accidentally trusting attacker-controlled metadata.
type GoogleIDTokenClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Audience      string
	Issuer        string
	ExpiresAt     time.Time
	IssuedAt      time.Time
}

// GoogleIDTokenVerifier verifies Google-signed ID tokens. Construct one via
// NewGoogleIDTokenVerifier and share it across requests; the JWKS cache and
// HTTP client are safe for concurrent use.
type GoogleIDTokenVerifier struct {
	HTTPClient *http.Client
	JWKSURL    string
	Now        func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// NewGoogleIDTokenVerifier returns a verifier that pulls Google's JWKS on
// demand and caches it. Pass nil for httpClient to use a sane default
// (15s timeout). The default HTTP client is purposely tighter than
// http.DefaultClient (which has no timeout) so a slow JWKS fetch cannot
// stall the auth handler indefinitely.
func NewGoogleIDTokenVerifier(httpClient *http.Client) *GoogleIDTokenVerifier {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &GoogleIDTokenVerifier{
		HTTPClient: httpClient,
		JWKSURL:    googleJWKSURL,
		Now:        time.Now,
		keys:       map[string]*rsa.PublicKey{},
	}
}

// Verify parses idToken, verifies its signature against Google's JWKS, and
// checks issuer / audience / expiry / email_verified. audience MUST be the
// OAuth client_id this server is registered as — passing an empty string is
// an error and indicates a misconfiguration.
func (v *GoogleIDTokenVerifier) Verify(ctx context.Context, idToken, audience string) (*GoogleIDTokenClaims, error) {
	if strings.TrimSpace(idToken) == "" {
		return nil, errors.New("id_token is empty")
	}
	if strings.TrimSpace(audience) == "" {
		return nil, errors.New("audience is required")
	}

	keyFn := func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("id_token header missing kid")
		}
		return v.publicKey(ctx, kid)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(""), // we validate issuer manually against a set, not a single value
		jwt.WithLeeway(jwtLeeway),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.Now),
	)

	var claims jwt.MapClaims
	parsed, err := parser.ParseWithClaims(idToken, &claims, keyFn)
	if err != nil {
		return nil, fmt.Errorf("id_token verify: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("id_token is not valid")
	}

	iss, _ := claims["iss"].(string)
	if !contains(googleIssuers, iss) {
		return nil, fmt.Errorf("id_token issuer %q not allowed", iss)
	}

	aud, ok := extractAudience(claims["aud"])
	if !ok || aud != audience {
		return nil, errors.New("id_token audience mismatch")
	}

	emailVerified, _ := claims["email_verified"].(bool)
	if !emailVerified {
		return nil, errors.New("id_token email is not verified")
	}

	email, _ := claims["email"].(string)
	if email == "" {
		return nil, errors.New("id_token has no email claim")
	}

	out := &GoogleIDTokenClaims{
		Subject:       toString(claims["sub"]),
		Email:         email,
		EmailVerified: emailVerified,
		Name:          toString(claims["name"]),
		Picture:       toString(claims["picture"]),
		Audience:      aud,
		Issuer:        iss,
	}
	if expFloat, ok := claims["exp"].(float64); ok {
		out.ExpiresAt = time.Unix(int64(expFloat), 0)
	}
	if iatFloat, ok := claims["iat"].(float64); ok {
		out.IssuedAt = time.Unix(int64(iatFloat), 0)
	}
	return out, nil
}

// publicKey returns the RSA public key for kid, refreshing the cache when
// the kid is unknown or the cache is stale. Locking serialises refreshes so
// a key-rotation event does not stampede the JWKS endpoint.
func (v *GoogleIDTokenVerifier) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if key, ok := v.keys[kid]; ok && v.Now().Sub(v.fetchedAt) < jwksRefreshAfter {
		return key, nil
	}
	if err := v.refreshLocked(ctx); err != nil {
		return nil, err
	}
	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("no Google JWKS key matches kid %q", kid)
	}
	return key, nil
}

// SetKeys replaces the cached JWKS. Test-only convenience: keeps the prod
// path (refreshLocked + HTTP fetch) free of any "if test-mode" branching.
func (v *GoogleIDTokenVerifier) SetKeys(keys map[string]*rsa.PublicKey, fetchedAt time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys = make(map[string]*rsa.PublicKey, len(keys))
	for k, key := range keys {
		v.keys[k] = key
	}
	v.fetchedAt = fetchedAt
}

func (v *GoogleIDTokenVerifier) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("build JWKS request: %w", err)
	}
	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read JWKS body: %w", err)
	}

	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("parse JWKS body: %w", err)
	}

	next := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Alg != "" && k.Alg != "RS256" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		eInt := 0
		for _, b := range eBytes {
			eInt = eInt<<8 + int(b)
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}
		next[k.Kid] = pub
	}
	if len(next) == 0 {
		return errors.New("JWKS contained no usable RSA keys")
	}
	v.keys = next
	v.fetchedAt = v.Now()
	return nil
}

func extractAudience(raw any) (string, bool) {
	switch v := raw.(type) {
	case string:
		return v, v != ""
	case []any:
		// Multi-audience tokens are legal in OIDC but Google's tokens for
		// our flow are single-valued. Reject the multi-audience case rather
		// than picking one and hoping — it would let an attacker who can
		// mint a multi-aud token for two clients (one we trust, one they
		// control) feed it back as if it were ours.
		if len(v) == 1 {
			if s, ok := v[0].(string); ok && s != "" {
				return s, true
			}
		}
		return "", false
	default:
		return "", false
	}
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
