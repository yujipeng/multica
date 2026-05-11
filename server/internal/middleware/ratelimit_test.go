package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_AllowsWithinLimit(t *testing.T) {
	rl := NewRateLimiter(5, time.Second)
	for i := 0; i < 5; i++ {
		if !rl.Allow("k") {
			t.Fatalf("request %d: expected Allow=true within limit", i)
		}
	}
}

func TestRateLimiter_DeniesAboveLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Hour)
	for i := 0; i < 3; i++ {
		if !rl.Allow("k") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if rl.Allow("k") {
		t.Fatal("4th request should be denied")
	}
}

func TestRateLimiter_SeparateKeys(t *testing.T) {
	rl := NewRateLimiter(1, time.Hour)
	if !rl.Allow("a") {
		t.Fatal("first key should pass")
	}
	if !rl.Allow("b") {
		t.Fatal("second key should pass (separate bucket)")
	}
	if rl.Allow("a") {
		t.Fatal("key a should be exhausted")
	}
}

func TestRateLimiter_ResetAfterWindow(t *testing.T) {
	rl := NewRateLimiter(1, 50*time.Millisecond)
	if !rl.Allow("k") {
		t.Fatal("first should pass")
	}
	if rl.Allow("k") {
		t.Fatal("second within window should be denied")
	}
	time.Sleep(70 * time.Millisecond)
	if !rl.Allow("k") {
		t.Fatal("should be allowed after window reset")
	}
}

func TestIPRateLimit_Middleware(t *testing.T) {
	rl := NewRateLimiter(2, time.Hour)
	mw := IPRateLimit(rl)
	called := 0
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/send-code", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := makeReq(); w.Code != http.StatusOK {
		t.Fatalf("req 1: expected 200, got %d", w.Code)
	}
	if w := makeReq(); w.Code != http.StatusOK {
		t.Fatalf("req 2: expected 200, got %d", w.Code)
	}
	if w := makeReq(); w.Code != http.StatusTooManyRequests {
		t.Fatalf("req 3: expected 429, got %d", w.Code)
	}
	if called != 2 {
		t.Fatalf("handler should have run twice, got %d", called)
	}
}

func TestUserOrIPRateLimit_KeysByUser(t *testing.T) {
	rl := NewRateLimiter(1, time.Hour)
	mw := UserOrIPRateLimit(rl)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Same IP, two distinct users → both pass (bucketed by user).
	req := httptest.NewRequest(http.MethodPost, "/api/issues", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-User-ID", "user-a")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("user-a should pass, got %d", w.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/issues", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	req2.Header.Set("X-User-ID", "user-b")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("user-b should pass (different bucket), got %d", w2.Code)
	}

	// Second request for user-a → 429.
	req3 := httptest.NewRequest(http.MethodPost, "/api/issues", nil)
	req3.RemoteAddr = "1.2.3.4:1234"
	req3.Header.Set("X-User-ID", "user-a")
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, req3)
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("user-a second req should 429, got %d", w3.Code)
	}
}

func TestClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
	if got := clientIP(req); got != "203.0.113.1" {
		t.Fatalf("expected leftmost XFF entry, got %q", got)
	}
}
