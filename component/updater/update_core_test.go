package updater

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCoreBaseName(t *testing.T) {
	fmt.Println("Core base name =", DefaultCoreUpdater.CoreBaseName())
}

func TestAtomicReplaceCopyFailureLeavesTargetUntouched(t *testing.T) {
	src, dst, metadata := replacementFixture(t)
	fileOps := defaultFileOperations()
	copyErr := errors.New("injected copy failure")
	fileOps.copy = func(dst io.Writer, src io.Reader) (int64, error) {
		n, _ := io.CopyN(dst, src, 3)
		return n, copyErr
	}

	replaced, err := atomicReplaceFile(src, dst, metadata, true, fileOps)
	if !errors.Is(err, copyErr) {
		t.Fatalf("expected copy error, got %v", err)
	}
	if replaced {
		t.Fatal("target reported as replaced after copy failure")
	}
	assertFileContent(t, dst, "old core")
	assertNoStagedFiles(t, dst)
}

func TestAtomicReplaceSignFailureLeavesTargetUntouched(t *testing.T) {
	src, dst, metadata := replacementFixture(t)
	fileOps := defaultFileOperations()
	signErr := errors.New("injected signing failure")
	fileOps.sign = func(string) error { return signErr }

	replaced, err := atomicReplaceFile(src, dst, metadata, true, fileOps)
	if !errors.Is(err, signErr) {
		t.Fatalf("expected signing error, got %v", err)
	}
	if replaced {
		t.Fatal("target reported as replaced after signing failure")
	}
	assertFileContent(t, dst, "old core")
	assertNoStagedFiles(t, dst)
}

func TestAtomicReplaceRenameFailureLeavesTargetUntouched(t *testing.T) {
	src, dst, metadata := replacementFixture(t)
	fileOps := defaultFileOperations()
	renameErr := errors.New("injected rename failure")
	fileOps.sign = func(string) error { return nil }
	fileOps.verify = func(string) error { return nil }
	fileOps.rename = func(string, string) error { return renameErr }

	replaced, err := atomicReplaceFile(src, dst, metadata, true, fileOps)
	if !errors.Is(err, renameErr) {
		t.Fatalf("expected rename error, got %v", err)
	}
	if replaced {
		t.Fatal("target reported as replaced after rename failure")
	}
	assertFileContent(t, dst, "old core")
	assertNoStagedFiles(t, dst)
}

func TestAtomicReplaceSuccessPreservesModeAndCleansTemp(t *testing.T) {
	src, dst, metadata := replacementFixture(t)
	fileOps := defaultFileOperations()
	var signed, verified bool
	fileOps.sign = func(path string) error {
		signed = true
		if filepath.Dir(path) != filepath.Dir(dst) {
			t.Fatalf("replacement staged outside target directory: %s", path)
		}
		return nil
	}
	fileOps.verify = func(string) error {
		verified = true
		return nil
	}

	replaced, err := atomicReplaceFile(src, dst, metadata, true, fileOps)
	if err != nil {
		t.Fatalf("atomicReplaceFile() error = %v", err)
	}
	if !replaced || !signed || !verified {
		t.Fatalf("replaced=%v signed=%v verified=%v", replaced, signed, verified)
	}
	assertFileContent(t, dst, "new core contents")
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o751); got != want {
		t.Fatalf("target mode = %v, want %v", got, want)
	}
	assertNoStagedFiles(t, dst)
}

func TestCleanStagedFilesRemovesOrphans(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "verge-mihomo")
	orphan := filepath.Join(dir, stagedFilePrefix(dst)+"orphan")
	unrelated := filepath.Join(dir, ".unrelated")
	if err := os.WriteFile(orphan, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cleanStagedFiles(dst); err != nil {
		t.Fatalf("cleanStagedFiles() error = %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan still exists or stat failed unexpectedly: %v", err)
	}
	assertFileContent(t, unrelated, "keep")
}

func TestRollbackRestoresBackup(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "backup")
	current := filepath.Join(dir, "current")
	writeTestFile(t, backup, "old core", 0o751)
	writeTestFile(t, current, "new core", 0o700)
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	fileOps := defaultFileOperations()
	if runtime.GOOS == "windows" {
		if err = os.Remove(current); err != nil {
			t.Fatal(err)
		}
	}

	if err = (&CoreUpdater{}).rollback(backup, current, metadataFromFileInfo(info), fileOps); err != nil {
		t.Fatalf("rollback() error = %v", err)
	}
	assertFileContent(t, current, "old core")
	if runtime.GOOS != "windows" {
		assertFileContent(t, backup, "old core")
		currentInfo, statErr := os.Stat(current)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if got, want := currentInfo.Mode().Perm(), os.FileMode(0o751); got != want {
			t.Fatalf("rolled back mode = %v, want %v", got, want)
		}
	}
}

func replacementFixture(t *testing.T) (src, dst string, metadata fileMetadata) {
	t.Helper()
	dir := t.TempDir()
	src = filepath.Join(dir, "downloaded-core")
	dst = filepath.Join(dir, "verge-mihomo")
	writeTestFile(t, src, "new core contents", 0o700)
	writeTestFile(t, dst, "old core", 0o751)
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	return src, dst, metadataFromFileInfo(info)
}

func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s content = %q, want %q", path, got, want)
	}
}

func assertNoStagedFiles(t *testing.T, dst string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(dst), stagedFilePrefix(dst)+"*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staged files were not cleaned: %v", matches)
	}
}
