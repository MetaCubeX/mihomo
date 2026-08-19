//go:build aix || android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package updater

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicReplacePreservesOwnership(t *testing.T) {
	src, dst, metadata := replacementFixture(t)
	before, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	beforeOwnership := ownershipFromFileInfo(before)
	fileOps := defaultFileOperations()
	fileOps.sign = func(string) error { return nil }
	fileOps.verify = func(string) error { return nil }

	if _, err = atomicReplaceFile(src, dst, metadata, true, fileOps); err != nil {
		t.Fatalf("atomicReplaceFile() error = %v", err)
	}
	after, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	afterOwnership := ownershipFromFileInfo(after)
	if !beforeOwnership.valid || !afterOwnership.valid {
		t.Skip("filesystem ownership metadata unavailable")
	}
	if beforeOwnership.uid != afterOwnership.uid || beforeOwnership.gid != afterOwnership.gid {
		t.Fatalf(
			"target ownership = %d:%d, want %d:%d",
			afterOwnership.uid,
			afterOwnership.gid,
			beforeOwnership.uid,
			beforeOwnership.gid,
		)
	}
}

func TestBackupPreservesMetadata(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "verge-mihomo")
	backupDir := filepath.Join(dir, "meta-backup")
	backup := filepath.Join(backupDir, filepath.Base(current))
	writeTestFile(t, current, "old core", 0o751)
	before, err := os.Stat(current)
	if err != nil {
		t.Fatal(err)
	}
	beforeOwnership := ownershipFromFileInfo(before)

	moved, err := (&CoreUpdater{}).backup(current, backup, backupDir, defaultFileOperations())
	if err != nil {
		t.Fatalf("backup() error = %v", err)
	}
	if moved {
		t.Fatal("Unix backup unexpectedly moved the current executable")
	}
	assertFileContent(t, current, "old core")
	assertFileContent(t, backup, "old core")
	after, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := after.Mode().Perm(), os.FileMode(0o751); got != want {
		t.Fatalf("backup mode = %v, want %v", got, want)
	}
	afterOwnership := ownershipFromFileInfo(after)
	if beforeOwnership.valid && afterOwnership.valid &&
		(beforeOwnership.uid != afterOwnership.uid || beforeOwnership.gid != afterOwnership.gid) {
		t.Fatalf(
			"backup ownership = %d:%d, want %d:%d",
			afterOwnership.uid,
			afterOwnership.gid,
			beforeOwnership.uid,
			beforeOwnership.gid,
		)
	}
}
