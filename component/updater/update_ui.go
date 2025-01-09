package updater

import (
	"archive/zip"
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

func (u *UIUpdater) downloadUI() error {
	err := u.prepareUIPath()
	if err != nil {
		return fmt.Errorf("prepare UI path failed: %w", err)
	}

	data, err := downloadForBytes(u.externalUIURL)
	if err != nil {
		return fmt.Errorf("can't download  file: %w", err)
	}

	saved := path.Join(C.Path.HomeDir(), "download.zip")
	if err = saveFile(data, saved); err != nil {
		return fmt.Errorf("can't save zip file: %w", err)
	}
	defer os.Remove(saved)

	err = cleanup(u.externalUIPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("cleanup exist file error: %w", err)
		}
	}

	unzipFolder, err := unzip(saved, C.Path.HomeDir())
	if err != nil {
		return fmt.Errorf("can't extract zip file: %w", err)
	}

	err = os.Rename(unzipFolder, u.externalUIPath)
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
	var extractedFolder string
	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
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
		if extractedFolder == "" {
			extractedFolder = filepath.Dir(fpath)
		}
	}
	return extractedFolder, nil
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
