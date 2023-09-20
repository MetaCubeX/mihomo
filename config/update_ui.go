package config

import (
	"archive/zip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

var (
	ExternalUIURL    string
	ExternalUIPath   string
)

var xdMutex sync.Mutex

func UpdateUI() error {
	xdMutex.Lock()
	defer xdMutex.Unlock()

	if ExternalUIPath == "" || ExternalUIURL == "" {
		return fmt.Errorf("ExternalUI configure incomplete")
	}

	err := cleanup(ExternalUIPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("cleanup exist file error: %w", err)
		}
	}

	data, err := downloadForBytes(ExternalUIURL)
	if err != nil {
		return fmt.Errorf("can't download  file: %w", err)
	}

	saved := path.Join(ExternalUIPath, "download.zip")
	if saveFile(data, saved) != nil {
		return fmt.Errorf("can't save zip file: %w", err)
	}
	defer os.Remove(saved)

	unzipFolder, err := unzip(saved, ExternalUIPath)
	if err != nil {
		return fmt.Errorf("can't extract zip file: %w", err)
	}

	files, err := ioutil.ReadDir(unzipFolder)
	if err != nil {
		return fmt.Errorf("error reading source folder: %w", err)
	}

	for _, file := range files {
		err = os.Rename(filepath.Join(unzipFolder, file.Name()), filepath.Join(ExternalUIPath, file.Name()))
		if err != nil {
			return nil
		}
	}
	defer os.Remove(unzipFolder)
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
		if path == root {
			// skip root itself
			return nil
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
