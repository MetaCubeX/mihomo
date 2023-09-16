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

	C "github.com/Dreamacro/clash/constant"
)

const xdURL = "https://codeload.github.com/MetaCubeX/metacubexd/zip/refs/heads/gh-pages"
const yacdURL = "https://codeload.github.com/MetaCubeX/Yacd-meta/zip/refs/heads/gh-pages"

var xdMutex sync.Mutex

func UpdateXD() error {
	xdMutex.Lock()
	defer xdMutex.Unlock()

	err := cleanup(C.UIPath)
	if err != nil {
		return fmt.Errorf("cleanup exist file error: %w", err)
	}

	data, err := downloadForBytes(xdURL)
	if err != nil {
		return fmt.Errorf("can't download XD file: %w", err)
	}

	saved := path.Join(C.UIPath, "xd.zip")
	if saveFile(data, saved) != nil {
		return fmt.Errorf("can't save XD zip file: %w", err)
	}
	defer os.Remove(saved)

	err = unzip(saved, C.UIPath)
	if err != nil {
		return fmt.Errorf("can't extract XD zip file: %w", err)
	}

	files, err := ioutil.ReadDir(path.Join(C.UIPath, "metacubexd-gh-pages"))
	if err != nil {
		return fmt.Errorf("Error reading source folder: %w", err)
	}

	for _, file := range files {
		err = os.Rename(filepath.Join(path.Join(C.UIPath, "metacubexd-gh-pages"), file.Name()), filepath.Join(C.UIPath, file.Name()))
		if err != nil {
			return fmt.Errorf("Error renaming file: %w", err)
		}
	}
	defer os.Remove(path.Join(C.UIPath, "metacubexd-gh-pages"))
	return nil
}

func UpdateYacd() error {
	xdMutex.Lock()
	defer xdMutex.Unlock()

	err := cleanup(C.UIPath)
	if err != nil {
		return fmt.Errorf("cleanup exist file error: %w", err)
	}

	data, err := downloadForBytes(yacdURL)
	if err != nil {
		return fmt.Errorf("can't download Yacd zip file: %w", err)
	}

	saved := path.Join(C.UIPath, "yacd.zip")
	if saveFile(data, saved) != nil {
		return fmt.Errorf("can't save Yacd file: %w", err)
	}
	defer os.Remove(saved)

	err = unzip(saved, C.UIPath)
	if err != nil {
		return fmt.Errorf("can't extract Yacd zip file: %w", err)
	}

	files, err := ioutil.ReadDir(path.Join(C.UIPath, "Yacd-meta-gh-pages"))
	if err != nil {
		return fmt.Errorf("Error reading source folder: %w", err)
	}

	for _, file := range files {
		err = os.Rename(filepath.Join(path.Join(C.UIPath, "Yacd-meta-gh-pages"), file.Name()), filepath.Join(C.UIPath, file.Name()))
		if err != nil {
			return fmt.Errorf("Error renaming file: %w", err)
		}
	}
	defer os.Remove(path.Join(C.UIPath, "Yacd-meta-gh-pages"))
	return nil
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
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

func cleanup(root string) error {
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
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
		} else {
			if err := os.Remove(path); err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
		}
		return nil
	})
}
