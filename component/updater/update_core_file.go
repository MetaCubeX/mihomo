package updater

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type fileMetadata struct {
	mode      os.FileMode
	ownership fileOwnership
}

type fileOperations struct {
	copy    func(io.Writer, io.Reader) (int64, error)
	rename  func(string, string) error
	sign    func(string) error
	verify  func(string) error
	syncDir func(string) error
}

func defaultFileOperations() fileOperations {
	return fileOperations{
		copy:    io.Copy,
		rename:  os.Rename,
		sign:    signCoreFile,
		verify:  verifyCoreFile,
		syncDir: syncDirectory,
	}
}

func metadataFromFileInfo(info os.FileInfo) fileMetadata {
	return fileMetadata{
		mode:      info.Mode(),
		ownership: ownershipFromFileInfo(info),
	}
}

// stageFile copies src into a unique file beside dst.  The destination is not
// touched until commitStagedFile atomically renames the fully prepared file.
func stageFile(src, dst string, metadata fileMetadata, sign bool, fileOps fileOperations) (tempPath string, err error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("opening source %s: %w", src, err)
	}
	srcOpen := true
	defer func() {
		if srcOpen {
			_ = srcFile.Close()
		}
	}()

	tempFile, err := os.CreateTemp(filepath.Dir(dst), stagedFilePrefix(dst))
	if err != nil {
		return "", fmt.Errorf("creating replacement beside %s: %w", dst, err)
	}
	createdPath := tempFile.Name()
	tempPath = createdPath
	tempOpen := true
	keepTemp := false
	defer func() {
		if tempOpen {
			_ = tempFile.Close()
		}
		if !keepTemp {
			_ = os.Remove(createdPath)
		}
	}()

	if _, err = fileOps.copy(tempFile, srcFile); err != nil {
		return "", fmt.Errorf("copying %s: %w", src, err)
	}
	if err = tempFile.Sync(); err != nil {
		return "", fmt.Errorf("syncing replacement %s: %w", tempPath, err)
	}
	if err = tempFile.Close(); err != nil {
		tempOpen = false
		return "", fmt.Errorf("closing replacement %s: %w", tempPath, err)
	}
	tempOpen = false
	if err = srcFile.Close(); err != nil {
		srcOpen = false
		return "", fmt.Errorf("closing source %s: %w", src, err)
	}
	srcOpen = false

	if err = applyFileMetadata(tempPath, metadata); err != nil {
		return "", err
	}
	if sign {
		if err = fileOps.sign(tempPath); err != nil {
			return "", fmt.Errorf("signing replacement: %w", err)
		}
		// codesign may rewrite the file.  Reapply trusted metadata before the
		// final sync and verification.
		if err = applyFileMetadata(tempPath, metadata); err != nil {
			return "", err
		}
	}
	if err = syncFile(tempPath); err != nil {
		return "", err
	}
	if sign {
		if err = fileOps.verify(tempPath); err != nil {
			return "", fmt.Errorf("verifying replacement signature: %w", err)
		}
	}

	keepTemp = true
	return tempPath, nil
}

func applyFileMetadata(path string, metadata fileMetadata) error {
	if err := applyFileOwnership(path, metadata.ownership); err != nil {
		return fmt.Errorf("preserving ownership on %s: %w", path, err)
	}

	mode := metadata.mode.Perm() | metadata.mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("preserving mode on %s: %w", path, err)
	}
	return nil
}

func commitStagedFile(tempPath, dst string, fileOps fileOperations) (replaced bool, err error) {
	if err = fileOps.rename(tempPath, dst); err != nil {
		return false, fmt.Errorf("renaming %s to %s: %w", tempPath, dst, err)
	}
	if err = fileOps.syncDir(filepath.Dir(dst)); err != nil {
		return true, fmt.Errorf("syncing destination directory: %w", err)
	}
	return true, nil
}

func atomicReplaceFile(src, dst string, metadata fileMetadata, sign bool, fileOps fileOperations) (replaced bool, err error) {
	tempPath, err := stageFile(src, dst, metadata, sign, fileOps)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = os.Remove(tempPath)
	}()
	return commitStagedFile(tempPath, dst, fileOps)
}

func atomicCopyFile(src, dst string, fileOps fileOperations) (replaced bool, err error) {
	info, err := os.Stat(src)
	if err != nil {
		return false, fmt.Errorf("stating source %s: %w", src, err)
	}
	return atomicReplaceFile(src, dst, metadataFromFileInfo(info), false, fileOps)
}

func stagedFilePrefix(dst string) string {
	return "." + filepath.Base(dst) + ".update-"
}

// cleanStagedFiles removes orphaned files left if a previous updater process
// was killed before its deferred cleanup could run.
func cleanStagedFiles(dst string) error {
	dir := filepath.Dir(dst)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	prefix := stagedFilePrefix(dst)
	var cleanupErr error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		if err = os.Remove(filepath.Join(dir, entry.Name())); err != nil && cleanupErr == nil {
			cleanupErr = err
		}
	}
	return cleanupErr
}
