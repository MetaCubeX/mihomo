package config

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Dreamacro/clash/common/convert"
	"github.com/Dreamacro/clash/component/mmdb"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

func downloadMMDB(path string) (err error) {
	resp, err := doGet("https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	return err
}

func initMMDB() error {
	if _, err := os.Stat(C.Path.MMDB()); os.IsNotExist(err) {
		log.Infoln("Can't find MMDB, start download")
		if err := downloadMMDB(C.Path.MMDB()); err != nil {
			return fmt.Errorf("can't download MMDB: %w", err)
		}
	}

	if !mmdb.Verify() {
		log.Warnln("MMDB invalid, remove and download")
		if err := os.Remove(C.Path.MMDB()); err != nil {
			return fmt.Errorf("can't remove invalid MMDB: %w", err)
		}

		if err := downloadMMDB(C.Path.MMDB()); err != nil {
			return fmt.Errorf("can't download MMDB: %w", err)
		}
	}

	return nil
}

func downloadGeoSite(path string) (err error) {
	resp, err := doGet("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	return err
}

func initGeoSite() error {
	if _, err := os.Stat(C.Path.GeoSite()); os.IsNotExist(err) {
		log.Infoln("Can't find GeoSite.dat, start download")
		if err := downloadGeoSite(C.Path.GeoSite()); err != nil {
			return fmt.Errorf("can't download GeoSite.dat: %w", err)
		}
		log.Infoln("Download GeoSite.dat finish")
	}

	return nil
}

// Init prepare necessary files
func Init(dir string) error {
	// initial homedir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("can't create config directory %s: %w", dir, err)
		}
	}

	// initial config.yaml
	if _, err := os.Stat(C.Path.Config()); os.IsNotExist(err) {
		log.Infoln("Can't find config, create a initial config file")
		f, err := os.OpenFile(C.Path.Config(), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("can't create file %s: %w", C.Path.Config(), err)
		}
		_, _ = f.Write([]byte(`mixed-port: 7890`))
		_ = f.Close()
	}

	// initial mmdb
	if err := initMMDB(); err != nil {
		return fmt.Errorf("can't initial MMDB: %w", err)
	}

	// initial GeoSite
	if err := initGeoSite(); err != nil {
		return fmt.Errorf("can't initial GeoSite: %w", err)
	}
	return nil
}

func doGet(url string) (resp *http.Response, err error) {
	var req *http.Request
	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	convert.SetUserAgent(req.Header)

	resp, err = http.DefaultClient.Do(req)
	return
}
