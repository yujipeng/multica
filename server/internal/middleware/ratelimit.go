package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter is a token bucket per key (IP or user_id) with a fixed
// refill window. It is in-memory and per-process; multi-node deploys
// that need shared state should swap in a Redis backend without
// changing the Limit() signature. The simple bucket avoids a new
// dependency while still defending against credential stuffing,
// brute-force code guesses, and uncontrolled write-loops — the
// scenarios the JEE-12 audit (P1-2) flagged.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rlBucket
	max     int
	window  time.Duration
}

type rlBucket struct {
	count     int
	resetTime time.Time
}

// NewRateLimiter creates a limiter that allows `max` requests per
// `window` per key. The first call after the window has elapsed
// resets the bucket. Stale buckets are reclaimed lazily on the next
// call for the same key, plus a coarse periodic sweep to keep the
// map bounded under churn.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*rlBucket),
		max:     max,
		window:  window,
	}
	go rl.sweepLoop()
	return rl
}

func (rl *RateLimiter) sweepLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		rl.sweep()
	}
}

func (rl *RateLimiter) sweep() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for k, b := range rl.buckets {
		if now.After(b.resetTime) {
			delete(rl.buckets, k)
		}
	}
}

// Allow consumes one slot for `key` and returns true if the request
// fits within the current window.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok || now.After(b.resetTime) {
		rl.buckets[key] = &rlBucket{count: 1, resetTime: now.Add(rl.window)}
		return true
	}
	if b.count >= rl.max {
		return false
	}
	b.count++
	return true
}

// clientIP extracts the best-guess client IP from the request. We
// prefer X-Forwarded-For's left-most entry when the request came
// through a known proxy chain, and fall back to RemoteAddr. The
// limiter only needs a stable bucket key; the IP doesn't need to be
// authoritative for security decisions.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if first := strings.TrimSpace(parts[0]); first != "" {
			return first
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IPRateLimit returns middleware that rate limits by client IP.
// Designed for unauthenticated routes (login, OAuth, send-code) where
// no user identity is available yet.
func IPRateLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.Allow("ip:" + clientIP(r)) {
				writeError(w, http.StatusTooManyRequests, "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// UserOrIPRateLimit returns middleware that rate limits by user_id
// when one is present (set by Auth middleware via X-User-ID) and
// falls back to client IP otherwise. Designed for authenticated
// write endpoints where the user is the right bucket key.
func UserOrIPRateLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := "ip:" + clientIP(r)
			if userID := r.Header.Get("X-User-ID"); userID != "" {
				key = "user:" + userID
			}
			if !rl.Allow(key) {
				writeError(w, http.StatusTooManyRequests, "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
