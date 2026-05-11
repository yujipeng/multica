package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBodyLimit_AllowsSmallBody(t *testing.T) {
	var got []byte
	h := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		got = b
		w.WriteHeader(http.StatusOK)
	}))

	body := strings.NewReader(`{"hello":"world"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/issues", body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if string(got) != `{"hello":"world"}` {
		t.Fatalf("body roundtrip: got %q", got)
	}
}

func TestBodyLimit_RejectsOversizedBody(t *testing.T) {
	h := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Fatal("expected read error on oversized body")
		}
		// MaxBytesReader sets the response status when the read fails.
		// The handler is responsible for writing the actual error body;
		// we just verify the read fails as expected.
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))

	oversized := bytes.Repeat([]byte("x"), DefaultMaxBodyBytes+1024)
	req := httptest.NewRequest(http.MethodPost, "/api/issues", bytes.NewReader(oversized))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestBodyLimit_SkipsUploadPath(t *testing.T) {
	// /api/upload-file must NOT be wrapped — its handler reapplies its own
	// 100 MiB cap, and the global 1 MiB cap would defeat that.
	h := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body should succeed on skipped path: %v", err)
		}
		if len(b) <= DefaultMaxBodyBytes {
			t.Fatalf("expected oversized body to pass through, got %d bytes", len(b))
		}
		w.WriteHeader(http.StatusOK)
	}))

	oversized := bytes.Repeat([]byte("x"), DefaultMaxBodyBytes+1024)
	req := httptest.NewRequest(http.MethodPost, "/api/upload-file", bytes.NewReader(oversized))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on skipped path, got %d", w.Code)
	}
}

func TestBodyLimit_LargeBucketForDaemonMessages(t *testing.T) {
	// Daemon task message batches are larger than 1 MiB but still need a
	// ceiling — verify the dedicated bucket is in effect.
	h := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body within large bucket should succeed: %v", err)
		}
		if len(b) <= DefaultMaxBodyBytes {
			t.Fatalf("body should exceed the default cap to prove we picked the large bucket")
		}
		w.WriteHeader(http.StatusOK)
	}))

	mid := DefaultMaxBodyBytes + 1024 // smaller than LargeBodyMaxBytes
	body := bytes.Repeat([]byte("x"), mid)
	req := httptest.NewRequest(http.MethodPost, "/api/daemon/tasks/abc/messages", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestBodyLimit_SkipsSafeMethods(t *testing.T) {
	// GET / HEAD / OPTIONS should pass through unmodified — they don't
	// carry meaningful bodies and wrapping them with MaxBytesReader
	// occasionally breaks proxies that send empty bodies.
	h := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For a GET we typically don't read the body; just ensure the
		// handler runs.
		w.WriteHeader(http.StatusOK)
	}))

	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(m, "/api/issues", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("method %s: expected 200, got %d", m, w.Code)
		}
	}
}
