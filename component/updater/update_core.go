package updater

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

const (
	baseReleaseURL    = "https://github.com/MetaCubeX/mihomo/releases/latest/download/"
	versionReleaseURL = "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"

	baseAlphaURL    = "https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/"
	versionAlphaURL = "https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/version.txt"

	// MaxPackageFileSize is a maximum package file length in bytes. The largest
	// package whose size is limited by this constant currently has the size of
	// approximately 32 MiB.
	MaxPackageFileSize = 32 * 1024 * 1024
)

const (
	ReleaseChannel = "release"
	AlphaChannel   = "alpha"
)

// CoreUpdater is the mihomo updater.
// modify from https://github.com/AdguardTeam/AdGuardHome/blob/595484e0b3fb4c457f9bb727a6b94faa78a66c5f/internal/updater/updater.go
type CoreUpdater struct {
	mu sync.Mutex
}

var DefaultCoreUpdater = CoreUpdater{}

func (u *CoreUpdater) CoreBaseName() string {
	switch runtime.GOARCH {
	case "arm":
		// mihomo-linux-armv5
		return fmt.Sprintf("mihomo-%s-%sv%s", runtime.GOOS, runtime.GOARCH, features.GOARM)
	case "arm64":
		if runtime.GOOS == "android" {
			// mihomo-android-arm64-v8
			return fmt.Sprintf("mihomo-%s-%s-v8", runtime.GOOS, runtime.GOARCH)
		} else {
			// mihomo-linux-arm64
			return fmt.Sprintf("mihomo-%s-%s", runtime.GOOS, runtime.GOARCH)
		}
	case "mips", "mipsle":
		// mihomo-linux-mips-hardfloat
		return fmt.Sprintf("mihomo-%s-%s-%s", runtime.GOOS, runtime.GOARCH, features.GOMIPS)
	case "amd64":
		// mihomo-linux-amd64-v1
		return fmt.Sprintf("mihomo-%s-%s-%s", runtime.GOOS, runtime.GOARCH, features.GOAMD64)
	default:
		// mihomo-linux-386
		// mihomo-linux-mips64
		// mihomo-linux-riscv64
		// mihomo-linux-s390x
		return fmt.Sprintf("mihomo-%s-%s", runtime.GOOS, runtime.GOARCH)
	}
}

func (u *CoreUpdater) Update(currentExePath string, channel string, force bool) (err error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	info, err := os.Stat(currentExePath)
	if err != nil {
		return fmt.Errorf("check currentExePath %q: %w", currentExePath, err)
	}

	baseURL := baseAlphaURL
	versionURL := versionAlphaURL
	switch strings.ToLower(channel) {
	case ReleaseChannel:
		baseURL = baseReleaseURL
		versionURL = versionReleaseURL
	case AlphaChannel:
		break
	default: // auto
		if !strings.HasPrefix(C.Version, "alpha") {
			baseURL = baseReleaseURL
			versionURL = versionReleaseURL
		}
	}

	latestVersion, err := u.getLatestVersion(versionURL)
	if err != nil {
		return fmt.Errorf("get latest version: %w", err)
	}
	log.Infoln("current version %s, latest version %s", C.Version, latestVersion)

	if latestVersion == C.Version && !force {
		// don't change this output, some downstream dependencies on the upgrader's output fields
		return fmt.Errorf("update error: already using latest version %s", C.Version)
	}

	defer func() {
		if err != nil {
			log.Errorln("updater: failed: %v", err)
		} else {
			log.Infoln("updater: finished")
		}
	}()

	// ---- prepare ----
	mihomoBaseName := u.CoreBaseName()
	packageName := mihomoBaseName + "-" + latestVersion
	if runtime.GOOS == "windows" {
		packageName = packageName + ".zip"
	} else {
		packageName = packageName + ".gz"
	}
	packageURL := baseURL + packageName
	log.Infoln("updater: updating using url: %s", packageURL)

	workDir := filepath.Dir(currentExePath)
	backupDir := filepath.Join(workDir, "meta-backup")
	updateDir := filepath.Join(workDir, "meta-update")
	packagePath := filepath.Join(updateDir, packageName)
	//log.Infoln(packagePath)

	updateExeName := mihomoBaseName
	if runtime.GOOS == "windows" {
		updateExeName = updateExeName + ".exe"
	}
	log.Infoln("updateExeName: %s", updateExeName)
	updateExePath := filepath.Join(updateDir, updateExeName)
	backupExePath := filepath.Join(backupDir, filepath.Base(currentExePath))

	defer u.clean(updateDir)

	err = u.download(updateDir, packagePath, packageURL)
	if err != nil {
		return fmt.Errorf("downloading: %w", err)
	}

	err = u.unpack(updateDir, packagePath, info.Mode())
	if err != nil {
		return fmt.Errorf("unpacking: %w", err)
	}

	err = u.backup(currentExePath, backupExePath, backupDir)
	if err != nil {
		return fmt.Errorf("backuping: %w", err)
	}

	err = u.copyFile(updateExePath, currentExePath)
	if err != nil {
		return fmt.Errorf("replacing: %w", err)
	}

	return nil
}

func (u *CoreUpdater) getLatestVersion(versionURL string) (version string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, versionURL, http.MethodGet, nil, nil, mihomoHttp.WithCAOption(ca.Option{ZeroTrust: true}))
	if err != nil {
		return "", err
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	content := strings.TrimRight(string(body), "\n")
	return content, nil
}

// download package file and save it to disk
func (u *CoreUpdater) download(updateDir, packagePath, packageURL string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, packageURL, http.MethodGet, nil, nil, mihomoHttp.WithCAOption(ca.Option{ZeroTrust: true}))
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	log.Debugln("updateDir %s", updateDir)
	err = os.Mkdir(updateDir, 0o755)
	if err != nil {
		return fmt.Errorf("mkdir error: %w", err)
	}

	log.Debugln("updater: saving package to file %s", packagePath)
	// Create the output file
	wc, err := os.OpenFile(packagePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("os.OpenFile(%s): %w", packagePath, err)
	}

	defer func() {
		closeErr := wc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	log.Debugln("updater: reading http body")
	// This use of io.Copy is now safe, because we limited body's Reader.
	n, err := io.Copy(wc, io.LimitReader(resp.Body, MaxPackageFileSize))
	if err != nil {
		return fmt.Errorf("io.Copy(): %w", err)
	}
	if n == MaxPackageFileSize {
		// Use whether n is equal to MaxPackageFileSize to determine whether the limit has been reached.
		// It is also possible that the size of the downloaded file is exactly the same as the maximum limit,
		// but we should not consider this too rare situation.
		return fmt.Errorf("attempted to read more than %d bytes", MaxPackageFileSize)
	}
	log.Debugln("updater: downloaded package to file %s", packagePath)

	return nil
}

// unpack extracts the files from the downloaded archive.
func (u *CoreUpdater) unpack(updateDir, packagePath string, fileMode os.FileMode) error {
	log.Infoln("updater: unpacking package")
	if strings.HasSuffix(packagePath, ".zip") {
		_, err := u.zipFileUnpack(packagePath, updateDir, fileMode)
		if err != nil {
			return fmt.Errorf(".zip unpack failed: %w", err)
		}

	} else if strings.HasSuffix(packagePath, ".gz") {
		_, err := u.gzFileUnpack(packagePath, updateDir, fileMode)
		if err != nil {
			return fmt.Errorf(".gz unpack failed: %w", err)
		}

	} else {
		return fmt.Errorf("unknown package extension")
	}

	return nil
}

// backup creates a backup of the current executable file.
func (u *CoreUpdater) backup(currentExePath, backupExePath, backupDir string) (err error) {
	log.Infoln("updater: backing up current ExecFile:%s to %s", currentExePath, backupExePath)
	_ = os.Mkdir(backupDir, 0o755)

	// On Windows, since the running executable cannot be overwritten or deleted, it uses os.Rename to move the file to the backup path.
	// On other platforms, it copies the file to the backup path, preserving the original file and its permissions.
	// The backup directory is created if it does not exist.
	if runtime.GOOS == "windows" {
		err = os.Rename(currentExePath, backupExePath)
	} else {
		err = u.copyFile(currentExePath, backupExePath)
	}
	if err != nil {
		return err
	}

	return nil
}

// clean removes the temporary directory itself and all it's contents.
func (u *CoreUpdater) clean(updateDir string) {
	_ = os.RemoveAll(updateDir)
}

// Unpack a single .gz file to the specified directory
// Existing files are overwritten
// All files are created inside outDir, subdirectories are not created
// Return the output file name
func (u *CoreUpdater) gzFileUnpack(gzfile, outDir string, fileMode os.FileMode) (outputName string, err error) {
	f, err := os.Open(gzfile)
	if err != nil {
		return "", fmt.Errorf("os.Open(): %w", err)
	}

	defer func() {
		closeErr := f.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip.NewReader(): %w", err)
	}

	defer func() {
		closeErr := gzReader.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	// Get the original file name from the .gz file header
	originalName := gzReader.Header.Name
	if originalName == "" {
		// Fallback: remove the .gz extension from the input file name if the header doesn't provide the original name
		originalName = filepath.Base(gzfile)
		originalName = strings.TrimSuffix(originalName, ".gz")
	}

	outputName = filepath.Join(outDir, originalName)

	// Create the output file
	wc, err := os.OpenFile(outputName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return "", fmt.Errorf("os.OpenFile(%s): %w", outputName, err)
	}

	defer func() {
		closeErr := wc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	// Copy the contents of the gzReader to the output file
	_, err = io.Copy(wc, gzReader)
	if err != nil {
		return "", fmt.Errorf("io.Copy(): %w", err)
	}

	return outputName, nil
}

// Unpack a single file from .zip file to the specified directory
// Existing files are overwritten
// All files are created inside 'outDir', subdirectories are not created
// Return the output file name
func (u *CoreUpdater) zipFileUnpack(zipfile, outDir string, fileMode os.FileMode) (outputName string, err error) {
	zrc, err := zip.OpenReader(zipfile)
	if err != nil {
		return "", fmt.Errorf("zip.OpenReader(): %w", err)
	}

	defer func() {
		closeErr := zrc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	if len(zrc.File) == 0 {
		return "", fmt.Errorf("no files in the zip archive")
	}

	// Assuming the first file in the zip archive is the target file
	zf := zrc.File[0]
	var rc io.ReadCloser
	rc, err = zf.Open()
	if err != nil {
		return "", fmt.Errorf("zip file Open(): %w", err)
	}

	defer func() {
		closeErr := rc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	fi := zf.FileInfo()
	name := fi.Name()
	outputName = filepath.Join(outDir, name)

	if fi.IsDir() {
		return "", fmt.Errorf("the target file is a directory")
	}

	var wc io.WriteCloser
	wc, err = os.OpenFile(outputName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return "", fmt.Errorf("os.OpenFile(): %w", err)
	}

	defer func() {
		closeErr := wc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	_, err = io.Copy(wc, rc)
	if err != nil {
		return "", fmt.Errorf("io.Copy(): %w", err)
	}

	return outputName, nil
}

// Copy file on disk
func (u *CoreUpdater) copyFile(src, dst string) (err error) {
	rc, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("os.Open(%s): %w", src, err)
	}

	defer func() {
		closeErr := rc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	info, err := rc.Stat()
	if err != nil {
		return fmt.Errorf("rc.Stat(): %w", err)
	}

	// Create the output file
	// If the file does not exist, creates it with permissions perm (before umask);
	// otherwise truncates it before writing, without changing permissions.
	wc, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		// On some file system (such as Android's /data) maybe return error: "text file busy"
		// Let's delete the target file and recreate it
		err = os.Remove(dst)
		if err != nil {
			return fmt.Errorf("os.Remove(%s): %w", dst, err)
		}
		wc, err = os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
		if err != nil {
			return fmt.Errorf("os.OpenFile(%s): %w", dst, err)
		}
	}

	defer func() {
		closeErr := wc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(wc, rc)
	if err != nil {
		return fmt.Errorf("io.Copy(): %w", err)
	}

	if runtime.GOOS == "darwin" {
		err = exec.Command("/usr/bin/codesign", "--sign", "-", dst).Run()
		if err != nil {
			log.Warnln("codesign failed: %v", err)
		}
	}

	log.Infoln("updater: copy: %s to %s", src, dst)
	return nil
}
