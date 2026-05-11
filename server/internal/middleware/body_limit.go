package middleware

import (
	"net/http"
	"strings"
)

// DefaultMaxBodyBytes is the per-request body cap applied by BodyLimit
// to every JSON / form endpoint that does not opt in to a larger cap.
// 1 MiB comfortably fits an oversized issue description or a batch of
// chat messages without permitting an authenticated client to OOM the
// process by streaming gigabytes into pgx.
const DefaultMaxBodyBytes = 1 << 20

// LargeBodyMaxBytes is the cap used for endpoints that legitimately
// accept bigger payloads — daemon task message batches and the
// importer-style endpoints. We still want a ceiling: unbounded body is
// what the audit (JEE-12 P1-8) flagged.
const LargeBodyMaxBytes = 8 << 20

// bodyLimitSkipPrefixes lists paths whose handlers reapply
// http.MaxBytesReader with a different (larger) cap. The middleware
// skips them so its smaller cap does not become the bottleneck.
//
// Keep the list small and explicit. New endpoints that need a custom
// cap should either (a) reapply MaxBytesReader inside the handler
// (matching the file.go/feedback.go convention) and be added here, or
// (b) call SetBodyLimit on the request before the global middleware
// runs (not currently used).
var bodyLimitSkipPrefixes = []string{
	"/api/upload-file",          // multipart upload, capped to 100 MiB internally
	"/api/me/onboarding",        // PatchOnboarding / ImportStarterContent set own caps
	"/api/feedback",             // CreateFeedback sets its own cap
}

// bodyLimitLargeBucketPrefixes lists paths that legitimately exceed
// DefaultMaxBodyBytes but should still be capped — typically daemon
// telemetry batches.
var bodyLimitLargeBucketPrefixes = []string{
	"/api/daemon/tasks/", // ReportTaskMessages: message batches
}

// BodyLimit wraps r.Body in an http.MaxBytesReader so any handler that
// calls json.NewDecoder(r.Body).Decode(&req) is implicitly capped at
// DefaultMaxBodyBytes. Routes listed in bodyLimitSkipPrefixes are left
// alone so their handlers can apply their own (typically larger)
// caps; routes in bodyLimitLargeBucketPrefixes get LargeBodyMaxBytes.
//
// GET / HEAD / OPTIONS requests bypass the wrap entirely — they should
// not carry a body, and wrapping noisy header-only requests adds no
// safety while occasionally breaking proxies that send empty bodies.
func BodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		for _, p := range bodyLimitSkipPrefixes {
			if strings.HasPrefix(path, p) {
				next.ServeHTTP(w, r)
				return
			}
		}
		limit := int64(DefaultMaxBodyBytes)
		for _, p := range bodyLimitLargeBucketPrefixes {
			if strings.HasPrefix(path, p) {
				limit = LargeBodyMaxBytes
				break
			}
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}
