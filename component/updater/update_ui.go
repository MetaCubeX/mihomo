package updater

import (
	"archive/tar"
	"archive/zip"
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
	err := u.prepareUIPath()
	if err != nil {
		return fmt.Errorf("prepare UI path failed: %w", err)
	}

	data, err := downloadForBytes(u.externalUIURL)
	if err != nil {
		return fmt.Errorf("can't download file: %w", err)
	}

	fileType := detectFileType(data)
	if fileType == typeUnknown {
		return fmt.Errorf("unknown or unsupported file type")
	}

	ext := ".zip"
	if fileType == typeTarGzip {
		ext = ".tgz"
	}

	saved := path.Join(C.Path.HomeDir(), "download"+ext)
	log.Debugln("compression Type: %s", ext)
	if err = saveFile(data, saved); err != nil {
		return fmt.Errorf("can't save compressed file: %w", err)
	}
	defer os.Remove(saved)

	err = cleanup(u.externalUIPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("cleanup exist file error: %w", err)
		}
	}

	extractedFolder, err := extract(saved, C.Path.HomeDir())
	if err != nil {
		return fmt.Errorf("can't extract compressed file: %w", err)
	}

	err = os.Rename(extractedFolder, u.externalUIPath)
	if err != nil {
		return fmt.Errorf("rename UI folder failed: %w", err)
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

func unzip(src, dest string) (string, error) {
	r, err := zip.OpenReader(src)
	if err != nil {
		return "", err
	}
	defer r.Close()

	// check whether or not only exists singleRoot dir
	rootDir := ""
	isSingleRoot := true
	rootItemCount := 0
	for _, f := range r.File {
		parts := strings.Split(strings.Trim(f.Name, "/"), "/")
		if len(parts) == 0 {
			continue
		}

		if len(parts) == 1 {
			isDir := strings.HasSuffix(f.Name, "/")
			if !isDir {
				isSingleRoot = false
				break
			}

			if rootDir == "" {
				rootDir = parts[0]
			}
			rootItemCount++
		}
	}

	if rootItemCount != 1 {
		isSingleRoot = false
	}

	// build the dir of extraction
	var extractedFolder string
	if isSingleRoot && rootDir != "" {
		// if the singleRoot, use it directly
		log.Debugln("Match the singleRoot")
		extractedFolder = filepath.Join(dest, rootDir)
		log.Debugln("extractedFolder: %s", extractedFolder)
	} else {
		log.Debugln("Match the multiRoot")
		// or put the files/dirs into new dir
		baseName := filepath.Base(src)
		baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))
		extractedFolder = filepath.Join(dest, baseName)

		for i := 1; ; i++ {
			if _, err := os.Stat(extractedFolder); os.IsNotExist(err) {
				break
			}
			extractedFolder = filepath.Join(dest, fmt.Sprintf("%s_%d", baseName, i))
		}
		log.Debugln("extractedFolder: %s", extractedFolder)
	}

	for _, f := range r.File {
		var fpath string
		if isSingleRoot && rootDir != "" {
			fpath = filepath.Join(dest, f.Name)
		} else {
			fpath = filepath.Join(extractedFolder, f.Name)
		}

		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return "", fmt.Errorf("invalid file path: %s", fpath)
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return "", err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return "", err
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return "", err
		}
	}
	return extractedFolder, nil
}

func untgz(src, dest string) (string, error) {
	file, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	rootDir := ""
	isSingleRoot := true
	rootItemCount := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		parts := strings.Split(cleanTarPath(header.Name), string(os.PathSeparator))
		if len(parts) == 0 {
			continue
		}

		if len(parts) == 1 {
			isDir := header.Typeflag == tar.TypeDir
			if !isDir {
				isSingleRoot = false
				break
			}

			if rootDir == "" {
				rootDir = parts[0]
			}
			rootItemCount++
		}
	}

	if rootItemCount != 1 {
		isSingleRoot = false
	}

	file.Seek(0, 0)
	gzr, _ = gzip.NewReader(file)
	tr = tar.NewReader(gzr)

	var extractedFolder string
	if isSingleRoot && rootDir != "" {
		log.Debugln("Match the singleRoot")
		extractedFolder = filepath.Join(dest, rootDir)
		log.Debugln("extractedFolder: %s", extractedFolder)
	} else {
		log.Debugln("Match the multiRoot")
		baseName := filepath.Base(src)
		baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))
		baseName = strings.TrimSuffix(baseName, ".tar")
		extractedFolder = filepath.Join(dest, baseName)

		for i := 1; ; i++ {
			if _, err := os.Stat(extractedFolder); os.IsNotExist(err) {
				break
			}
			extractedFolder = filepath.Join(dest, fmt.Sprintf("%s_%d", baseName, i))
		}
		log.Debugln("extractedFolder: %s", extractedFolder)
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		var fpath string
		if isSingleRoot && rootDir != "" {
			fpath = filepath.Join(dest, cleanTarPath(header.Name))
		} else {
			fpath = filepath.Join(extractedFolder, cleanTarPath(header.Name))
		}

		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return "", fmt.Errorf("invalid file path: %s", fpath)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(fpath, os.FileMode(header.Mode)); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				return "", err
			}
			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return "", err
			}
			outFile.Close()
		}
	}
	return extractedFolder, nil
}

func extract(src, dest string) (string, error) {
	srcLower := strings.ToLower(src)
	switch {
	case strings.HasSuffix(srcLower, ".tar.gz") ||
		strings.HasSuffix(srcLower, ".tgz"):
		return untgz(src, dest)
	case strings.HasSuffix(srcLower, ".zip"):
		return unzip(src, dest)
	default:
		return "", fmt.Errorf("unsupported file format: %s", src)
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
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		} else {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		return nil
	})
}
