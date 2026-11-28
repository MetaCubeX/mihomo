//go:build darwin

package updater

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReplaceFileAtomicallyPreservesDarwinFlags(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")

	if err := os.WriteFile(src, []byte("new-core"), 0o700); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := os.WriteFile(dst, []byte("old-core"), 0o755); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	if err := unix.Chflags(dst, unix.UF_HIDDEN); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("cannot set darwin file flags in test environment: %v", err)
		}
		t.Fatalf("set darwin flags on dst: %v", err)
	}

	if err := DefaultCoreUpdater.replaceFileAtomically(src, dst); err != nil {
		t.Fatalf("replace file atomically: %v", err)
	}

	var st syscall.Stat_t
	if err := syscall.Stat(dst, &st); err != nil {
		t.Fatalf("stat dst: %v", err)
	}

	if st.Flags&unix.UF_HIDDEN == 0 {
		t.Fatalf("expected UF_HIDDEN to be preserved, flags=%#x", st.Flags)
	}
}
