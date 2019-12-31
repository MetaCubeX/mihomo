package config

import (
	"fmt"
	"io"
	"net/http"
	"os"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

func downloadMMDB(path string) (err error) {
	resp, err := http.Get("https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	return err
}

// Init prepare necessary files
func Init(dir string) error {
	// initial homedir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0777); err != nil {
			return fmt.Errorf("Can't create config directory %s: %s", dir, err.Error())
		}
	}

	// initial config.yaml
	if _, err := os.Stat(C.Path.Config()); os.IsNotExist(err) {
		log.Infoln("Can't find config, create an empty file")
		os.OpenFile(C.Path.Config(), os.O_CREATE|os.O_WRONLY, 0644)
	}

	// initial mmdb
	if _, err := os.Stat(C.Path.MMDB()); os.IsNotExist(err) {
		log.Infoln("Can't find MMDB, start download")
		err := downloadMMDB(C.Path.MMDB())
		if err != nil {
			return fmt.Errorf("Can't download MMDB: %s", err.Error())
		}
	}
	return nil
}
