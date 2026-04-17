//go:build linux || darwin

package updater

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReplaceFileAtomicallyPreservesDestinationXattrs(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	name := testXattrName()
	want := []byte("preserved")

	if err := os.WriteFile(src, []byte("new-core"), 0o700); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := os.WriteFile(dst, []byte("old-core"), 0o755); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	if err := unix.Lsetxattr(dst, name, want, 0); err != nil {
		if isUnsupportedXattrErr(err) {
			t.Skipf("xattrs not supported in test environment: %v", err)
		}
		t.Fatalf("set xattr on dst: %v", err)
	}

	if err := DefaultCoreUpdater.replaceFileAtomically(src, dst); err != nil {
		t.Fatalf("replace file atomically: %v", err)
	}

	got, err := readXattr(dst, name)
	if err != nil {
		t.Fatalf("read xattr from dst: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected xattr value: got %q want %q", got, want)
	}
}

func readXattr(path, name string) ([]byte, error) {
	size, err := unix.Lgetxattr(path, name, nil)
	if err != nil {
		return nil, err
	}

	value := make([]byte, size)
	n, err := unix.Lgetxattr(path, name, value)
	if err != nil {
		return nil, err
	}

	return value[:n], nil
}

func testXattrName() string {
	if runtime.GOOS == "darwin" {
		return "com.mihomo.test"
	}

	return "user.mihomo.test"
}

func isUnsupportedXattrErr(err error) bool {
	return errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, syscall.EPERM)
}
