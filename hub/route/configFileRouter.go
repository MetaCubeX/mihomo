package route

import (
	"bytes"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/hub/executor"
	"github.com/go-chi/chi/v5"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func configFileRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/getConfigFile", getConfigFile)
	r.Put("/updateConfigFile", updateConfigFile)
	r.Put("/uploadConfigFile", uploadConfigFile)
	return r
}

func getConfigFile(w http.ResponseWriter, r *http.Request) {
	configFile, err := os.Open(C.Path.Config())
	defer configFile.Close()
	io.Copy(w, configFile)
	if err != nil {
		return
	}
}

func updateConfigFile(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	if contentType != "text/plain" {
		http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
		return
	}

	buf := bytes.NewBuffer(nil)
	_, err := io.Copy(buf, r.Body)
	if err != nil {
		return
	}
	_, err = testConfigFile(buf)
	if err != nil {
		http.Error(w, "config error,update failed", http.StatusOK)
		return
	}

	f, err := os.OpenFile(C.Path.Config(), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	defer f.Close()
	if err != nil {
		return
	}
	io.Copy(f, buf)
}

func exist(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func uploadConfigFile(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	ok := strings.Contains(contentType, "multipart/form-data")

	if !ok {
		http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
		return
	}
	// 100Mb
	r.ParseMultipartForm(1024 * 1024 * 100)
	file, fileInfo, err := r.FormFile("configFile")

	//Test config file
	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, file)
	if err != nil {
		return
	}
	_, err = testConfigFile(buf)
	if err != nil {
		http.Error(w, "config error,update failed", http.StatusOK)
		return
	}

	uploadFile := r.FormValue("filePath")
	newFile, err := backupFile(filepath.Join(uploadFile, fileInfo.Filename))
	if err != nil {
		return
	}
	io.Copy(newFile, file)
	newFile.Close()
	file.Close()
}

// backup old conifg
func backupFile(filepath string) (*os.File, error) {
	uploadFilePath := C.Path.Config()
	if filepath != "" {
		uploadFilePath = filepath
	}
	backupFilePath := uploadFilePath + ".bak"

	if exist(uploadFilePath) {
		if exist(backupFilePath) {
			err := os.Remove(backupFilePath)
			if err != nil {
				return nil, err
			}
		}
		err := os.Rename(uploadFilePath, backupFilePath)
		if err != nil {
			return nil, err
		}
	}

	file, err := os.Create(uploadFilePath)
	//create file error,backup file
	if err != nil {
		if exist(backupFilePath) {
			err := os.Rename(backupFilePath, uploadFilePath)
			if err != nil {
				return nil, err
			}
		}
	}
	return file, nil
}

// Test config file
func testConfigFile(buf *bytes.Buffer) (*config.Config, error) {
	return executor.ParseWithBytes(buf.Bytes())
}
