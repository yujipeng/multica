package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/multica-ai/multica/server/internal/auth"
)

// ---------------------------------------------------------------------------
// resolveGoogleRedirectURI — P0-2 unit coverage
// ---------------------------------------------------------------------------

func TestResolveGoogleRedirectURI_EmptyRequestUsesPrimary(t *testing.T) {
	t.Setenv("GOOGLE_REDIRECT_URI", "https://app.example.com/auth/callback")
	t.Setenv("GOOGLE_REDIRECT_URI_ALLOWLIST", "")
	got, err := resolveGoogleRedirectURI("")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "https://app.example.com/auth/callback" {
		t.Errorf("got %q, want primary", got)
	}
}

func TestResolveGoogleRedirectURI_AllowsMatchingValue(t *testing.T) {
	t.Setenv("GOOGLE_REDIRECT_URI", "https://app.example.com/auth/callback")
	t.Setenv("GOOGLE_REDIRECT_URI_ALLOWLIST", "multica://oauth/callback,https://staging.example.com/auth/callback")
	got, err := resolveGoogleRedirectURI("multica://oauth/callback")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "multica://oauth/callback" {
		t.Errorf("got %q, want match", got)
	}
}

func TestResolveGoogleRedirectURI_RejectsAttackerValue(t *testing.T) {
	// P0-2: an attacker-controlled redirect_uri must NOT be forwarded to
	// Google. With only the primary set, anything but that primary must
	// fail closed.
	t.Setenv("GOOGLE_REDIRECT_URI", "https://app.example.com/auth/callback")
	t.Setenv("GOOGLE_REDIRECT_URI_ALLOWLIST", "")
	if _, err := resolveGoogleRedirectURI("https://attacker.example.com/steal"); err == nil {
		t.Fatal("expected attacker redirect_uri to be rejected")
	}
}

func TestResolveGoogleRedirectURI_RejectsWhenUnconfigured(t *testing.T) {
	t.Setenv("GOOGLE_REDIRECT_URI", "")
	t.Setenv("GOOGLE_REDIRECT_URI_ALLOWLIST", "")
	if _, err := resolveGoogleRedirectURI(""); err == nil {
		t.Fatal("expected error when neither env var is set")
	}
}

// ---------------------------------------------------------------------------
// GoogleLogin handler — end-to-end (P0-2 + P0-3) with stub Google endpoint
// ---------------------------------------------------------------------------

// stubGoogleTokenServer replaces oauth2.googleapis.com/token for tests. The
// helper drives a single Setenv-friendly URL through DI: the prod path uses
// http.PostForm against a hard-coded URL; we point the test at an
// httptest.Server by overriding GOOGLE_TOKEN_ENDPOINT (added below).
//
// Rather than thread a base URL through every layer we simply assert at the
// handler shape level: build the request, hand it to GoogleLogin, observe
// the status code. The minimum we want to prove:
//
//   - P0-2: a redirect_uri not in the allowlist is rejected BEFORE we hit
//     Google at all.
//   - P0-3: a Google response without an id_token is rejected; a Google
//     response whose id_token fails verification is also rejected.
//
// Both negative paths exercise only the new defensive code; the happy path
// is covered by the existing E2E suite which talks to real Google in
// integration mode.

func TestGoogleLogin_RejectsBadRedirectURI(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "client-123")
	t.Setenv("GOOGLE_CLIENT_SECRET", "shh")
	t.Setenv("GOOGLE_REDIRECT_URI", "https://app.example.com/auth/callback")
	t.Setenv("GOOGLE_REDIRECT_URI_ALLOWLIST", "")

	body := mustMarshal(t, map[string]string{
		"code":         "abc",
		"redirect_uri": "https://attacker.example.com/steal",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Stub a Google id-token verifier; we should never reach it.
	h := &Handler{GoogleIDVerifier: auth.NewGoogleIDTokenVerifier(nil)}
	h.GoogleLogin(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "redirect_uri") {
		t.Errorf("expected redirect_uri error, got %s", w.Body.String())
	}
}

// TestGoogleLogin_RejectsMissingIDToken proves P0-3 fails closed: even if
// Google returned a 200 with an access_token, the handler must refuse to
// log the user in when no id_token was returned (the old code silently
// fell back to userinfo).
func TestGoogleLogin_RejectsMissingIDToken(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "client-123")
	t.Setenv("GOOGLE_CLIENT_SECRET", "shh")
	t.Setenv("GOOGLE_REDIRECT_URI", "https://app.example.com/auth/callback")
	t.Setenv("GOOGLE_REDIRECT_URI_ALLOWLIST", "")

	// Stand up a fake Google token endpoint that returns access_token only.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "ya29.fake-access-token",
			"token_type":   "Bearer",
			// No id_token field.
		})
	}))
	defer tokenSrv.Close()
	t.Setenv(googleTokenEndpointEnv, tokenSrv.URL)

	body := mustMarshal(t, map[string]string{
		"code":         "abc",
		"redirect_uri": "https://app.example.com/auth/callback",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h := &Handler{GoogleIDVerifier: auth.NewGoogleIDTokenVerifier(nil)}
	h.GoogleLogin(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 (missing id_token), got %d: %s", w.Code, w.Body.String())
	}
}

// TestGoogleLogin_RejectsForgedIDToken proves P0-3 also catches the worst
// case: a Google response that *does* carry an id_token, but the token
// was signed by some other key / has the wrong audience. This emulates
// the cross-OAuth-app confused-deputy attack.
func TestGoogleLogin_RejectsForgedIDToken(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "client-123")
	t.Setenv("GOOGLE_CLIENT_SECRET", "shh")
	t.Setenv("GOOGLE_REDIRECT_URI", "https://app.example.com/auth/callback")
	t.Setenv("GOOGLE_REDIRECT_URI_ALLOWLIST", "")

	// Mint an id_token for a *different* aud than client-123.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-kid"
	verifier := auth.NewGoogleIDTokenVerifier(nil)
	verifier.SetKeys(map[string]*rsa.PublicKey{kid: &priv.PublicKey}, time.Now())

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":            "https://accounts.google.com",
		"aud":            "evil-client",
		"sub":            "9999",
		"email":          "victim@example.com",
		"email_verified": true,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(10 * time.Minute).Unix(),
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "ya29.fake",
			"id_token":     signed,
			"token_type":   "Bearer",
		})
	}))
	defer tokenSrv.Close()
	t.Setenv(googleTokenEndpointEnv, tokenSrv.URL)

	body := mustMarshal(t, map[string]string{
		"code":         "abc",
		"redirect_uri": "https://app.example.com/auth/callback",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h := &Handler{GoogleIDVerifier: verifier}
	h.GoogleLogin(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (audience mismatch), got %d: %s", w.Code, w.Body.String())
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
