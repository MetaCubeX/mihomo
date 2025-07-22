package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type UIUpdater struct {
	externalUIURL  string
	externalUIPath string
	autoDownloadUI bool

	mutex sync.Mutex
}

type compressionType int

const (
	typeUnknown compressionType = iota
	typeZip
	typeTarGzip
)

func (t compressionType) String() string {
	switch t {
	case typeZip:
		return "zip"
	case typeTarGzip:
		return "tar.gz"
	default:
		return "unknown"
	}
}

var DefaultUiUpdater = &UIUpdater{}

func NewUiUpdater(externalUI, externalUIURL, externalUIName string) *UIUpdater {
	updater := &UIUpdater{}
	// checkout externalUI exist
	if externalUI != "" {
		updater.autoDownloadUI = true
		updater.externalUIPath = C.Path.Resolve(externalUI)
	} else {
		// default externalUI path
		updater.externalUIPath = path.Join(C.Path.HomeDir(), "ui")
	}

	// checkout UIpath/name exist
	if externalUIName != "" {
		updater.autoDownloadUI = true
		updater.externalUIPath = path.Join(updater.externalUIPath, externalUIName)
	}

	if externalUIURL != "" {
		updater.externalUIURL = externalUIURL
	}
	return updater
}

func (u *UIUpdater) AutoDownloadUI() {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	if u.autoDownloadUI {
		dirEntries, _ := os.ReadDir(u.externalUIPath)
		if len(dirEntries) > 0 {
			log.Infoln("UI already exists, skip downloading")
		} else {
			log.Infoln("External UI downloading ...")
			err := u.downloadUI()
			if err != nil {
				log.Errorln("Error downloading UI: %s", err)
			}
		}
	}
}

func (u *UIUpdater) DownloadUI() error {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	return u.downloadUI()
}

func detectFileType(data []byte) compressionType {
	if len(data) < 4 {
		return typeUnknown
	}

	// Zip: 0x50 0x4B 0x03 0x04
	if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
		return typeZip
	}

	// GZip: 0x1F 0x8B
	if data[0] == 0x1F && data[1] == 0x8B {
		return typeTarGzip
	}

	return typeUnknown
}

func (u *UIUpdater) downloadUI() error {
	data, err := downloadForBytes(u.externalUIURL)
	if err != nil {
		return fmt.Errorf("can't download file: %w", err)
	}

	tmpDir := C.Path.Resolve("downloadUI.tmp")
	defer os.RemoveAll(tmpDir)

	os.RemoveAll(tmpDir) // cleanup tmp dir before extract
	log.Debugln("extractedFolder: %s", tmpDir)
	err = extract(data, tmpDir)
	if err != nil {
		return fmt.Errorf("can't extract compressed file: %w", err)
	}

	log.Debugln("cleanupFolder: %s", u.externalUIPath)
	err = cleanup(u.externalUIPath) // cleanup files in dir don't remove dir itself
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("cleanup exist file error: %w", err)
		}
	}

	err = u.prepareUIPath()
	if err != nil {
		return fmt.Errorf("prepare UI path failed: %w", err)
	}

	log.Debugln("moveFolder from %s to %s", tmpDir, u.externalUIPath)
	err = moveDir(tmpDir, u.externalUIPath) // move files from tmp to target
	if err != nil {
		return fmt.Errorf("move UI folder failed: %w", err)
	}
	return nil
}

func (u *UIUpdater) prepareUIPath() error {
	if _, err := os.Stat(u.externalUIPath); os.IsNotExist(err) {
		log.Infoln("dir %s does not exist, creating", u.externalUIPath)
		if err := os.MkdirAll(u.externalUIPath, os.ModePerm); err != nil {
			log.Warnln("create dir %s error: %s", u.externalUIPath, err)
		}
	}
	return nil
}

func unzip(data []byte, dest string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	// check whether or not only exists singleRoot dir

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		if !inDest(fpath, dest) {
			return fmt.Errorf("invalid file path: %s", fpath)
		}
		info := f.FileInfo()
		if info.IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue // disallow symlink
		}
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode().Perm())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func untgz(data []byte, dest string) error {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		fpath := filepath.Join(dest, header.Name)

		if !inDest(fpath, dest) {
			return fmt.Errorf("invalid file path: %s", fpath)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(fpath, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				return err
			}
			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode).Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}
	return nil
}

func extract(data []byte, dest string) error {
	fileType := detectFileType(data)
	log.Debugln("compression Type: %s", fileType)
	switch fileType {
	case typeZip:
		return unzip(data, dest)
	case typeTarGzip:
		return untgz(data, dest)
	default:
		return fmt.Errorf("unknown or unsupported file type")
	}
}

func cleanTarPath(path string) string {
	// remove prefix ./ or ../
	path = strings.TrimPrefix(path, "./")
	path = strings.TrimPrefix(path, "../")

	// normalize path
	path = filepath.Clean(path)

	// transfer delimiters to system std
	path = filepath.FromSlash(path)

	// remove prefix path delimiters
	path = strings.TrimPrefix(path, string(os.PathSeparator))

	return path
}

func cleanup(root string) error {
	dirEntryList, err := os.ReadDir(root)
	if err != nil {
		return err
	}

	for _, dirEntry := range dirEntryList {
		err = os.RemoveAll(filepath.Join(root, dirEntry.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

func moveDir(src string, dst string) error {
	dirEntryList, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	if len(dirEntryList) == 1 && dirEntryList[0].IsDir() {
		src = filepath.Join(src, dirEntryList[0].Name())
		log.Debugln("match the singleRoot: %s", src)
		dirEntryList, err = os.ReadDir(src)
		if err != nil {
			return err
		}
	}

	for _, dirEntry := range dirEntryList {
		err = os.Rename(filepath.Join(src, dirEntry.Name()), filepath.Join(dst, dirEntry.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

func inDest(fpath, dest string) bool {
	if rel, err := filepath.Rel(dest, fpath); err == nil {
		if filepath.IsLocal(rel) {
			return true
		}
	}
	return false
}
