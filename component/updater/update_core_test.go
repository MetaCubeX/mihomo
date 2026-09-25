package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCoreBaseName(t *testing.T) {
	fmt.Println("Core base name =", DefaultCoreUpdater.CoreBaseName())
}

func TestPrepareUpdateDirRemovesStaleContents(t *testing.T) {
	root := t.TempDir()
	updateDir := filepath.Join(root, "meta-update")

	if err := os.MkdirAll(updateDir, 0o755); err != nil {
		t.Fatalf("mkdir update dir: %v", err)
	}

	staleFile := filepath.Join(updateDir, "stale.txt")
	if err := os.WriteFile(staleFile, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	if err := DefaultCoreUpdater.prepareUpdateDir(updateDir); err != nil {
		t.Fatalf("prepare update dir: %v", err)
	}

	entries, err := os.ReadDir(updateDir)
	if err != nil {
		t.Fatalf("read update dir: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("expected clean update dir, got %d entries", len(entries))
	}
}

func TestReplaceFileAtomicallyReplacesDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("replaceFileAtomically is used on non-Windows platforms")
	}

	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")

	if err := os.WriteFile(src, []byte("new-core"), 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := os.WriteFile(dst, []byte("old-core"), 0o755); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	if err := DefaultCoreUpdater.replaceFileAtomically(src, dst); err != nil {
		t.Fatalf("replace file atomically: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}

	if string(got) != "new-core" {
		t.Fatalf("unexpected dst content: %q", string(got))
	}
}

func TestReplaceFileAtomicallyPreservesDestinationMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("replaceFileAtomically is used on non-Windows platforms")
	}

	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")

	if err := os.WriteFile(src, []byte("new-core"), 0o700); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := os.WriteFile(dst, []byte("old-core"), 0o755); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	if err := os.Chmod(dst, 0o751); err != nil {
		t.Fatalf("chmod dst: %v", err)
	}

	if err := DefaultCoreUpdater.replaceFileAtomically(src, dst); err != nil {
		t.Fatalf("replace file atomically: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}

	if got, want := info.Mode().Perm(), os.FileMode(0o751); got != want {
		t.Fatalf("unexpected dst mode: got %o want %o", got, want)
	}
}

func TestReplaceFileAtomicallyReplacesSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("replaceFileAtomically is used on non-Windows platforms")
	}

	root := t.TempDir()
	src := filepath.Join(root, "src")
	realDst := filepath.Join(root, "real-dst")
	linkDst := filepath.Join(root, "current")

	if err := os.WriteFile(src, []byte("new-core"), 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := os.WriteFile(realDst, []byte("old-core"), 0o755); err != nil {
		t.Fatalf("write real dst: %v", err)
	}

	if err := os.Symlink(realDst, linkDst); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if err := DefaultCoreUpdater.replaceFileAtomically(src, linkDst); err != nil {
		t.Fatalf("replace file atomically via symlink: %v", err)
	}

	linkInfo, err := os.Lstat(linkDst)
	if err != nil {
		t.Fatalf("lstat symlink dst: %v", err)
	}

	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected %s to remain a symlink", linkDst)
	}

	got, err := os.ReadFile(realDst)
	if err != nil {
		t.Fatalf("read real dst: %v", err)
	}

	if string(got) != "new-core" {
		t.Fatalf("unexpected real dst content: %q", string(got))
	}
}

func TestReplaceFileAtomicallyKeepsDestinationOnSourceError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("replaceFileAtomically is used on non-Windows platforms")
	}

	root := t.TempDir()
	dst := filepath.Join(root, "dst")

	if err := os.WriteFile(dst, []byte("old-core"), 0o755); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	err := DefaultCoreUpdater.replaceFileAtomically(filepath.Join(root, "missing-src"), dst)
	if err == nil {
		t.Fatal("expected replaceFileAtomically to fail for missing src")
	}

	got, readErr := os.ReadFile(dst)
	if readErr != nil {
		t.Fatalf("read dst: %v", readErr)
	}

	if string(got) != "old-core" {
		t.Fatalf("destination was modified on failure: %q", string(got))
	}
}
