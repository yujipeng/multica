package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// trackingDBTX is a fake DBTX that captures every SQL string that
// reaches the database layer. It returns errors from the row's Scan
// so the handler treats every query as a miss (PAT lookup fails,
// token-version lookup fails, etc.) — exactly the "no credential"
// world we want to simulate. The test then asserts which SQL strings
// were attempted, which is enough to prove or refute "Logout reached
// the BumpUserTokenVersion UPDATE".
type trackingDBTX struct {
	mu     sync.Mutex
	sqlSeen []string
}

type fakeRow struct{}

func (fakeRow) Scan(_ ...any) error { return pgx.ErrNoRows }

func (t *trackingDBTX) record(sql string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sqlSeen = append(t.sqlSeen, sql)
}

func (t *trackingDBTX) sawBump() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sqlSeen {
		if strings.Contains(s, "token_version = token_version + 1") {
			return true
		}
	}
	return false
}

func (t *trackingDBTX) Exec(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
	t.record(sql)
	return pgconn.CommandTag{}, nil
}

func (t *trackingDBTX) Query(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
	t.record(sql)
	return nil, pgx.ErrNoRows
}

func (t *trackingDBTX) QueryRow(_ context.Context, sql string, _ ...interface{}) pgx.Row {
	t.record(sql)
	return fakeRow{}
}

func newLogoutTestHandler() (*Handler, *trackingDBTX) {
	tx := &trackingDBTX{}
	h := &Handler{Queries: db.New(tx)}
	return h, tx
}

// TestLogout_IgnoresForgedXUserIDHeader anchors JEE-12 B-1: when no
// verifiable credential is present, /auth/logout MUST NOT bump
// anyone's token_version, even if the caller supplies an X-User-ID
// header. The bug pre-fix was: Logout read X-User-ID and bumped that
// user's token_version, allowing any anonymous client to force-logout
// any account given just its UUID.
func TestLogout_IgnoresForgedXUserIDHeader(t *testing.T) {
	h, tx := newLogoutTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	// Spoof what middleware.Auth would normally set. Logout is on the
	// public group, so no real middleware ran; the handler must not
	// trust this header.
	req.Header.Set("X-User-ID", "11111111-2222-3333-4444-555555555555")

	w := httptest.NewRecorder()
	h.Logout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("logout should still 200 for UX (cookie clear), got %d", w.Code)
	}
	if tx.sawBump() {
		t.Fatalf("Logout reached BumpUserTokenVersion with only X-User-ID header — B-1 regressed")
	}
	// Sanity: the cookie-clearing pass is still happening.
	if got := w.Header().Values("Set-Cookie"); len(got) == 0 {
		t.Fatalf("expected Set-Cookie deletions for logout UX, got none")
	}
}

// TestLogout_NoCredentialsIsNoop covers the totally-anonymous path:
// no header, no cookie, no Authorization — logout should still 200
// and clear cookies but never touch the database.
func TestLogout_NoCredentialsIsNoop(t *testing.T) {
	h, tx := newLogoutTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if tx.sawBump() {
		t.Fatalf("Logout bumped token_version with no credentials at all")
	}
}

// TestLogout_RejectsBearerWithInvalidSignature ensures a forged JWT
// (wrong secret) does not reach the bump. The PAT path is similar
// but harder to fake without a real DB; the JWT path is a clean
// end-to-end exercise of the signature check.
func TestLogout_RejectsBearerWithInvalidSignature(t *testing.T) {
	h, tx := newLogoutTestHandler()

	// A bogus, syntactically-valid-but-unsignable bearer. extractToken
	// will pick it up; jwt.Parse will reject it; authedUserIDFromRequest
	// must return ok=false and the bump must not fire.
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-jwt-just-three-segments.aaa.bbb")

	w := httptest.NewRecorder()
	h.Logout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if tx.sawBump() {
		t.Fatalf("Logout bumped token_version on an invalid JWT signature")
	}
}
