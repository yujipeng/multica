package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/internal/storage"
)

// TestServeLocalUpload covers the P0-1 fix: the /uploads/* route MUST
// refuse unauthenticated callers, MUST refuse cross-workspace access, and
// MUST refuse cross-user access for user-private assets.
//
// Each subtest writes a fresh file to the LocalStorage upload dir, then
// hits ServeLocalUpload as if chi had matched the route. The DB state
// (workspace + member) comes from setupHandlerTestFixture in
// handler_test.go.

func newLocalForTest(t *testing.T) (*storage.LocalStorage, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("LOCAL_UPLOAD_DIR", dir)
	t.Setenv("LOCAL_UPLOAD_BASE_URL", "")
	local := storage.NewLocalStorageFromEnv()
	if local == nil {
		t.Fatal("NewLocalStorageFromEnv returned nil")
	}
	return local, dir
}

func writeKey(t *testing.T, dir, key, body string) {
	t.Helper()
	full := filepath.Join(dir, key)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestServeLocalUpload_RequiresAuth(t *testing.T) {
	if testHandler == nil {
		t.Skip("test fixture not initialized; needs DATABASE_URL")
	}
	local, dir := newLocalForTest(t)
	writeKey(t, dir, "workspaces/"+testWorkspaceID+"/private.txt", "secret")

	req := httptest.NewRequest(http.MethodGet, "/uploads/workspaces/"+testWorkspaceID+"/private.txt", nil)
	// Intentionally NOT setting X-User-ID — Auth middleware would normally
	// gate this; ServeLocalUpload itself also requires X-User-ID via
	// requireUserID. The result must be 401.
	w := httptest.NewRecorder()
	testHandler.ServeLocalUpload(local).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() == "secret" {
		t.Fatal("response body leaked file contents to unauthenticated caller")
	}
}

func TestServeLocalUpload_RejectsForeignWorkspace(t *testing.T) {
	if testHandler == nil {
		t.Skip("test fixture not initialized; needs DATABASE_URL")
	}
	local, dir := newLocalForTest(t)
	foreignWs := "00000000-0000-0000-0000-000000000099"
	writeKey(t, dir, "workspaces/"+foreignWs+"/private.txt", "secret")

	req := httptest.NewRequest(http.MethodGet, "/uploads/workspaces/"+foreignWs+"/private.txt", nil)
	req.Header.Set("X-User-ID", testUserID)
	w := httptest.NewRecorder()
	testHandler.ServeLocalUpload(local).ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign-workspace request: expected 404, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() == "secret" {
		t.Fatal("file contents leaked across workspace boundary")
	}
}

func TestServeLocalUpload_AllowsOwnWorkspace(t *testing.T) {
	if testHandler == nil {
		t.Skip("test fixture not initialized; needs DATABASE_URL")
	}
	local, dir := newLocalForTest(t)
	writeKey(t, dir, "workspaces/"+testWorkspaceID+"/ok.txt", "hello")

	req := httptest.NewRequest(http.MethodGet, "/uploads/workspaces/"+testWorkspaceID+"/ok.txt", nil)
	req.Header.Set("X-User-ID", testUserID)
	w := httptest.NewRecorder()
	testHandler.ServeLocalUpload(local).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authorised request: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "hello" {
		t.Fatalf("body mismatch: got %q want %q", w.Body.String(), "hello")
	}
}

func TestServeLocalUpload_RejectsOtherUsersPrivateAsset(t *testing.T) {
	if testHandler == nil {
		t.Skip("test fixture not initialized; needs DATABASE_URL")
	}
	local, dir := newLocalForTest(t)
	otherUser := "00000000-0000-0000-0000-000000000123"
	writeKey(t, dir, "users/"+otherUser+"/avatar.png", "PNG")

	req := httptest.NewRequest(http.MethodGet, "/uploads/users/"+otherUser+"/avatar.png", nil)
	req.Header.Set("X-User-ID", testUserID)
	w := httptest.NewRecorder()
	testHandler.ServeLocalUpload(local).ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-user request: expected 404, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() == "PNG" {
		t.Fatal("response leaked another user's private asset")
	}
}

func TestServeLocalUpload_RejectsUnscopedKey(t *testing.T) {
	if testHandler == nil {
		t.Skip("test fixture not initialized; needs DATABASE_URL")
	}
	local, dir := newLocalForTest(t)
	writeKey(t, dir, "legacy.txt", "legacy")

	req := httptest.NewRequest(http.MethodGet, "/uploads/legacy.txt", nil)
	req.Header.Set("X-User-ID", testUserID)
	w := httptest.NewRecorder()
	testHandler.ServeLocalUpload(local).ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unscoped key: expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServeLocalUpload_RejectsPathTraversal(t *testing.T) {
	if testHandler == nil {
		t.Skip("test fixture not initialized; needs DATABASE_URL")
	}
	local, _ := newLocalForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/uploads/workspaces/"+testWorkspaceID+"/../../etc/passwd", nil)
	req.Header.Set("X-User-ID", testUserID)
	w := httptest.NewRecorder()
	testHandler.ServeLocalUpload(local).ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("path traversal: expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServeLocalUpload_RejectsTrailingSlashDirectoryListing(t *testing.T) {
	// P0-1 regression: a workspace member must NOT be able to coerce
	// http.ServeFile into emitting an HTML directory index by hitting
	// "/uploads/workspaces/<wsId>/" with a trailing slash. The old guard
	// (len(segments) < 3) accepted segments == ["workspaces", "<wsId>", ""]
	// because SplitN produces a 3-element slice for that input.
	if testHandler == nil {
		t.Skip("test fixture not initialized; needs DATABASE_URL")
	}
	local, dir := newLocalForTest(t)
	// Pre-create some files in the workspace dir; the test passes only if
	// none of these names appear in the response body.
	writeKey(t, dir, "workspaces/"+testWorkspaceID+"/secret-a.txt", "AAA")
	writeKey(t, dir, "workspaces/"+testWorkspaceID+"/secret-b.txt", "BBB")

	req := httptest.NewRequest(http.MethodGet, "/uploads/workspaces/"+testWorkspaceID+"/", nil)
	req.Header.Set("X-User-ID", testUserID)
	w := httptest.NewRecorder()
	testHandler.ServeLocalUpload(local).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("trailing-slash dir request: expected 404, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "secret-a.txt") || strings.Contains(body, "secret-b.txt") || strings.Contains(body, "<a href=") {
		t.Fatalf("response leaked directory contents: %q", body)
	}
}

func TestServeLocalUpload_RejectsTrailingSlashUserDir(t *testing.T) {
	// Same regression for the users/<userId>/ namespace.
	if testHandler == nil {
		t.Skip("test fixture not initialized; needs DATABASE_URL")
	}
	local, dir := newLocalForTest(t)
	writeKey(t, dir, "users/"+testUserID+"/avatar.png", "PNG")

	req := httptest.NewRequest(http.MethodGet, "/uploads/users/"+testUserID+"/", nil)
	req.Header.Set("X-User-ID", testUserID)
	w := httptest.NewRecorder()
	testHandler.ServeLocalUpload(local).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("user trailing-slash request: expected 404, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "avatar.png") || strings.Contains(w.Body.String(), "<a href=") {
		t.Fatalf("response leaked user-private dir listing")
	}
}

func TestServeLocalUpload_RejectsNestedDirectoryTarget(t *testing.T) {
	// Even when the third segment is non-empty, the resolved path must
	// not be a directory. Belt-and-suspenders against future key shapes.
	if testHandler == nil {
		t.Skip("test fixture not initialized; needs DATABASE_URL")
	}
	local, dir := newLocalForTest(t)
	// Create a nested directory with files; key segment count is fine
	// (workspaces/<wsId>/sub) but it resolves to a directory.
	writeKey(t, dir, "workspaces/"+testWorkspaceID+"/sub/inner.txt", "inner")

	req := httptest.NewRequest(http.MethodGet, "/uploads/workspaces/"+testWorkspaceID+"/sub", nil)
	req.Header.Set("X-User-ID", testUserID)
	w := httptest.NewRecorder()
	testHandler.ServeLocalUpload(local).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("nested dir target: expected 404, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "inner.txt") || strings.Contains(w.Body.String(), "<a href=") {
		t.Fatalf("response leaked nested directory listing")
	}
}

var _ = context.Background
