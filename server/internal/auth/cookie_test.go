package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsSecureCookie(t *testing.T) {
	cases := []struct {
		name           string
		frontendOrigin string
		want           bool
	}{
		{"https origin → Secure", "https://app.example.com", true},
		{"https with port", "https://app.example.com:8443", true},
		{"http origin → not Secure", "http://192.168.5.5:13000", false},
		{"http localhost → not Secure", "http://localhost:3000", false},
		{"empty → not Secure", "", false},
		{"malformed → not Secure", "::not-a-url", false},
		{"uppercase scheme still matches", "HTTPS://app.example.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FRONTEND_ORIGIN", tc.frontendOrigin)
			if got := isSecureCookie(); got != tc.want {
				t.Errorf("isSecureCookie() = %v, want %v (FRONTEND_ORIGIN=%q)", got, tc.want, tc.frontendOrigin)
			}
		})
	}
}

func TestCookieDomain(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"real domain", ".example.com", ".example.com"},
		{"bare domain", "example.com", "example.com"},
		{"IPv4 rejected", "192.168.5.5", ""},
		{"IPv4 with leading dot rejected", ".192.168.5.5", ""},
		{"IPv6 rejected", "::1", ""},
		{"IPv6 bracketed is not a valid IP literal → passthrough", "[::1]", "[::1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("COOKIE_DOMAIN", tc.env)
			if got := cookieDomain(); got != tc.want {
				t.Errorf("cookieDomain() = %q, want %q (COOKIE_DOMAIN=%q)", got, tc.want, tc.env)
			}
		})
	}
}

// TestSetAuthCookies_HTTPSelfHost covers the exact misconfiguration that
// shipped to users on LAN self-host: COOKIE_DOMAIN=<ip> + HTTP FRONTEND_ORIGIN.
// The cookie must land with no Domain attribute and Secure=false so browsers
// actually store it.
func TestSetAuthCookies_HTTPSelfHost(t *testing.T) {
	t.Setenv("FRONTEND_ORIGIN", "http://192.168.5.5:13000")
	t.Setenv("COOKIE_DOMAIN", "192.168.5.5")

	rec := httptest.NewRecorder()
	if err := SetAuthCookies(rec, "test-token"); err != nil {
		t.Fatalf("SetAuthCookies: %v", err)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies (auth + csrf), got %d", len(cookies))
	}
	for _, c := range cookies {
		if c.Secure {
			t.Errorf("cookie %q has Secure=true on HTTP origin; browser would reject it", c.Name)
		}
		if c.Domain != "" {
			t.Errorf("cookie %q has Domain=%q; IP-address Domain would be rejected by the browser (RFC 6265)", c.Name, c.Domain)
		}
	}
}

func TestSetAuthCookies_HTTPSProduction(t *testing.T) {
	t.Setenv("FRONTEND_ORIGIN", "https://app.example.com")
	t.Setenv("COOKIE_DOMAIN", "app.example.com")

	rec := httptest.NewRecorder()
	if err := SetAuthCookies(rec, "test-token"); err != nil {
		t.Fatalf("SetAuthCookies: %v", err)
	}

	for _, c := range rec.Result().Cookies() {
		if !c.Secure {
			t.Errorf("cookie %q missing Secure flag on HTTPS origin", c.Name)
		}
		if c.Domain != "app.example.com" {
			t.Errorf("cookie %q Domain = %q, want %q", c.Name, c.Domain, "app.example.com")
		}
	}
}

// TestClearAuthCookies_ClearsCloudFront covers the logout path: every
// CloudFront signed cookie set at login (Policy / Signature / Key-Pair-Id)
// must be invalidated, otherwise a logged-out user on a shared browser
// could keep reading private CDN assets for up to 30 days. Bug found in
// the JEE-12 audit (P1-3).
func TestClearAuthCookies_ClearsCloudFront(t *testing.T) {
	t.Setenv("FRONTEND_ORIGIN", "https://app.example.com")
	t.Setenv("COOKIE_DOMAIN", ".example.com")

	rec := httptest.NewRecorder()
	ClearAuthCookies(rec)

	wantClear := map[string]bool{
		AuthCookieName:             true,
		CSRFCookieName:             true,
		"CloudFront-Policy":        true,
		"CloudFront-Signature":     true,
		"CloudFront-Key-Pair-Id":   true,
	}

	for _, c := range rec.Result().Cookies() {
		if !wantClear[c.Name] {
			continue
		}
		if c.MaxAge != -1 {
			t.Errorf("cookie %q MaxAge = %d, want -1 (delete)", c.Name, c.MaxAge)
		}
		delete(wantClear, c.Name)
	}
	for missing := range wantClear {
		t.Errorf("cookie %q was not cleared", missing)
	}
}

// TestClearAuthCookies_CloudFrontAttributesMatchSet ensures the deletion
// cookies use the same (Secure, SameSite=None, Path=/) tuple as the
// cookies emitted by CloudFrontSigner.SignedCookies. A mismatched
// SameSite or Secure causes the browser to create a *new* tombstone
// cookie under a different key without overwriting the original — the
// CDN keeps serving private content. Anchored as a regression test for
// the JEE-12 audit P1-3 fix.
func TestClearAuthCookies_CloudFrontAttributesMatchSet(t *testing.T) {
	t.Setenv("FRONTEND_ORIGIN", "https://app.example.com")
	t.Setenv("COOKIE_DOMAIN", ".example.com")

	rec := httptest.NewRecorder()
	ClearAuthCookies(rec)

	for _, c := range rec.Result().Cookies() {
		if c.Name != "CloudFront-Policy" && c.Name != "CloudFront-Signature" && c.Name != "CloudFront-Key-Pair-Id" {
			continue
		}
		if !c.Secure {
			t.Errorf("cookie %q must be Secure to match login-time signed cookies", c.Name)
		}
		if c.SameSite != http.SameSiteNoneMode {
			t.Errorf("cookie %q SameSite = %v, want None (matches signed cookies)", c.Name, c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("cookie %q Path = %q, want /", c.Name, c.Path)
		}
	}
}
