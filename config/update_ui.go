package config

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
)

var (
	ExternalUIURL    string
	ExternalUIPath   string
	ExternalUIFolder string
	ExternalUIName   string
)
var (
	ErrIncompleteConf = errors.New("ExternalUI configure incomplete")
)
var xdMutex sync.Mutex

func UpdateUI() error {
	xdMutex.Lock()
	defer xdMutex.Unlock()

	err := prepare()
	if err != nil {
		return err
	}

	data, err := downloadForBytes(ExternalUIURL)
	if err != nil {
		return fmt.Errorf("can't download  file: %w", err)
	}

	saved := path.Join(C.Path.HomeDir(), "download.zip")
	if saveFile(data, saved) != nil {
		return fmt.Errorf("can't save zip file: %w", err)
	}
	defer os.Remove(saved)

	err = cleanup(ExternalUIFolder)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("cleanup exist file error: %w", err)
		}
	}

	unzipFolder, err := unzip(saved, C.Path.HomeDir())
	if err != nil {
		return fmt.Errorf("can't extract zip file: %w", err)
	}

	err = os.Rename(unzipFolder, ExternalUIFolder)
	if err != nil {
		return fmt.Errorf("can't rename folder: %w", err)
	}
	return nil
}

func prepare() error {
	if ExternalUIPath == "" || ExternalUIURL == "" {
		return ErrIncompleteConf
	}

	if ExternalUIName != "" {
		ExternalUIFolder = filepath.Clean(path.Join(ExternalUIPath, ExternalUIName))
		if _, err := os.Stat(ExternalUIPath); os.IsNotExist(err) {
			if err := os.MkdirAll(ExternalUIPath, os.ModePerm); err != nil {
				return err
			}
		}
	} else {
		ExternalUIFolder = ExternalUIPath
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
