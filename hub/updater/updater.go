package updater

import (
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

// modify from https://github.com/AdguardTeam/AdGuardHome/blob/595484e0b3fb4c457f9bb727a6b94faa78a66c5f/internal/updater/updater.go
// Updater is the Clash.Meta updater.
var (
	client http.Client

	goarch string
	goos   string
	goarm  string
	gomips string

	workDir         string
	versionCheckURL string

	// mu protects all fields below.
	mu sync.RWMutex

	// TODO(a.garipov): See if all of these fields actually have to be in
	// this struct.
	currentExeName string // 当前可执行文件
	updateDir      string // 更新目录
	packageName    string // 更新压缩文件
	backupDir      string // 备份目录
	backupExeName  string // 备份文件名
	updateExeName  string // 更新后的可执行文件
	unpackedFile   string

	baseURL       string = "https://ghproxy.com/https://github.com/MetaCubeX/Clash.Meta/releases/download/Prerelease-Alpha/clash.meta"
	versionURL    string = "https://github.com/MetaCubeX/Clash.Meta/releases/download/Prerelease-Alpha/version.txt"
	packageURL    string
	latestVersion string
)

type updateError struct {
	Message string
}

func (e *updateError) Error() string {
	return fmt.Sprintf("error: %s", e.Message)
}

// Update performs the auto-updater.  It returns an error if the updater failed.
// If firstRun is true, it assumes the configuration file doesn't exist.
func Update() (err error) {
	goos = runtime.GOOS
	goarch = runtime.GOARCH
	latestVersion = getLatestVersion()

	if latestVersion == constant.Version {
		err := &updateError{Message: "Already using latest version"}
		return err
	}

	updateDownloadURL()
	mu.Lock()
	defer mu.Unlock()

	log.Infoln("current version alpha-%s", constant.Version)

	defer func() {
		if err != nil {
			log.Errorln("updater: failed: %v", err)
		} else {
			log.Infoln("updater: finished")
		}
	}()

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting executable path: %w", err)
	}

	workDir = filepath.Dir(execPath)
	//log.Infoln("workDir %s", execPath)

	err = prepare(execPath)
	if err != nil {
		return fmt.Errorf("preparing: %w", err)
	}

	defer clean()

	err = downloadPackageFile()
	if err != nil {
		return fmt.Errorf("downloading package file: %w", err)
	}

	err = unpack()
	if err != nil {
		return fmt.Errorf("unpacking: %w", err)
	}

	err = replace()
	if err != nil {
		return fmt.Errorf("replacing: %w", err)
	}

	return nil
}

// VersionCheckURL returns the version check URL.
func VersionCheckURL() (vcu string) {
	mu.RLock()
	defer mu.RUnlock()

	return versionCheckURL
}

// prepare fills all necessary fields in Updater object.
func prepare(exePath string) (err error) {
	updateDir = filepath.Join(workDir, "meta-update")
	currentExeName = exePath
	_, pkgNameOnly := filepath.Split(packageURL)
	if pkgNameOnly == "" {
		return fmt.Errorf("invalid PackageURL: %q", packageURL)
	}

	packageName = filepath.Join(updateDir, pkgNameOnly)
	//log.Infoln(packageName)
	backupDir = filepath.Join(workDir, "meta-backup")

	if goos == "windows" {
		updateExeName = "clash.meta" + "-" + goos + "-" + goarch + ".exe"
	} else {
		updateExeName = "clash.meta" + "-" + goos + "-" + goarch
	}

	log.Infoln("updateExeName: %s ,currentExeName: %s", updateExeName, currentExeName)

	backupExeName = filepath.Join(backupDir, filepath.Base(exePath))
	updateExeName = filepath.Join(updateDir, updateExeName)

	log.Infoln(
		"updater: updating using url: %s",
		packageURL,
	)

	currentExeName = exePath
	_, err = os.Stat(currentExeName)
	if err != nil {
		return fmt.Errorf("checking %q: %w", currentExeName, err)
	}

	return nil
}

// unpack extracts the files from the downloaded archive.
func unpack() error {
	var err error
	_, pkgNameOnly := filepath.Split(packageURL)

	log.Debugln("updater: unpacking package")
	if strings.HasSuffix(pkgNameOnly, ".zip") {
		unpackedFile, err = zipFileUnpack(packageName, updateDir)
		if err != nil {
			return fmt.Errorf(".zip unpack failed: %w", err)
		}

	} else if strings.HasSuffix(pkgNameOnly, ".gz") {
		unpackedFile, err = gzFileUnpack(packageName, updateDir)
		if err != nil {
			return fmt.Errorf(".gz unpack failed: %w", err)
		}

	} else {
		return fmt.Errorf("unknown package extension")
	}

	return nil
}

// replace moves the current executable with the updated one and also copies the
// supporting files.
func replace() error {
	//err := copySupportingFiles(unpackedFiles, updateDir, workDir)
	//if err != nil {
	//	return fmt.Errorf("copySupportingFiles(%s, %s) failed: %w", updateDir, workDir, err)
	//}

	log.Infoln("updater: renaming: %s to %s", currentExeName, backupExeName)
	err := os.Rename(currentExeName, backupExeName)
	if err != nil {
		return err
	}

	if goos == "windows" {
		// rename fails with "File in use" error
		log.Infoln("copying:%s to %s", updateExeName, currentExeName)
		err = copyFile(updateExeName, currentExeName)
	} else {
		err = os.Rename(updateExeName, currentExeName)
	}
	if err != nil {
		return err
	}

	return nil
}

// clean removes the temporary directory itself and all it's contents.
func clean() {
	_ = os.RemoveAll(updateDir)
}

// MaxPackageFileSize is a maximum package file length in bytes. The largest
// package whose size is limited by this constant currently has the size of
// approximately 9 MiB.
const MaxPackageFileSize = 32 * 1024 * 1024

// Download package file and save it to disk
func downloadPackageFile() (err error) {
	var resp *http.Response
	resp, err = client.Get(packageURL)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	var r io.Reader
	r, err = LimitReader(resp.Body, MaxPackageFileSize)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}

	log.Debugln("updater: reading http body")
	// This use of ReadAll is now safe, because we limited body's Reader.
	body, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("io.ReadAll() failed: %w", err)
	}

	log.Debugln("updateDir %s", updateDir)
	err = os.Mkdir(updateDir, 0o755)
	if err != nil {
		fmt.Errorf("mkdir error: %w", err)
	}

	log.Debugln("updater: saving package to file %s", packageName)
	err = os.WriteFile(packageName, body, 0o755)
	if err != nil {
		return fmt.Errorf("os.WriteFile() failed: %w", err)
	}
	return nil
}

// Unpack a single .gz file to the specified directory
// Existing files are overwritten
// All files are created inside outDir, subdirectories are not created
// Return the output file name
func gzFileUnpack(gzfile, outDir string) (string, error) {
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

	outputName := filepath.Join(outDir, originalName)

	// Create the output file
	wc, err := os.OpenFile(
		outputName,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0o755,
	)
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
func zipFileUnpack(zipfile, outDir string) (string, error) {
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
	outputName := filepath.Join(outDir, name)

	if fi.IsDir() {
		return "", fmt.Errorf("the target file is a directory")
	}

	var wc io.WriteCloser
	wc, err = os.OpenFile(outputName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode())
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
func copyFile(src, dst string) error {
	d, e := os.ReadFile(src)
	if e != nil {
		return e
	}
	e = os.WriteFile(dst, d, 0o644)
	if e != nil {
		return e
	}
	return nil
}

func getLatestVersion() string {
	resp, err := http.Get(versionURL)
	if err != nil {
		return ""
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	content := strings.TrimRight(string(body), "\n")
	log.Infoln("latest:%s", content)
	return content
}

func updateDownloadURL() {
	var middle string

	if goarch == "arm" && goarm != "" {
		middle = fmt.Sprintf("-%s-%sv%s-%s", goos, goarch, goarm, latestVersion)
	} else if isMIPS(goarch) && gomips != "" {
		middle = fmt.Sprintf("-%s-%s-%s-%s", goos, goarch, gomips, latestVersion)
	} else {
		middle = fmt.Sprintf("-%s-%s-%s", goos, goarch, latestVersion)
	}

	if goos == "windows" {
		middle += ".zip"
	} else {
		middle += ".gz"
	}
	packageURL = baseURL + middle
	//log.Infoln(packageURL)
}

// isMIPS returns true if arch is any MIPS architecture.
func isMIPS(arch string) (ok bool) {
	switch arch {
	case
		"mips",
		"mips64",
		"mips64le",
		"mipsle":
		return true
	default:
		return false
	}
}
