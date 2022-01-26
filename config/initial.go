package config

import (
	"fmt"
	"io"
	"net/http"
	"os"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

func downloadGeoIP(path string) (err error) {
	resp, err := http.Get("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat")
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

func downloadGeoSite(path string) (err error) {
	resp, err := http.Get("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat")
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
		log.Infoln("Need GeoSite but can't find GeoSite.dat, start download")
		if err := downloadGeoSite(C.Path.GeoSite()); err != nil {
			return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
		}
		log.Infoln("Download GeoSite.dat finish")
	}

	return nil
}

func initGeoIP() error {
	if _, err := os.Stat(C.Path.GeoIP()); os.IsNotExist(err) {
		log.Infoln("Need GeoIP but can't find GeoIP.dat, start download")
		if err := downloadGeoIP(C.Path.GeoIP()); err != nil {
			return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
		}
		log.Infoln("Download GeoIP.dat finish")
	}

	return nil
}

// Init prepare necessary files
func Init(dir string) error {
	// initial homedir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("can't create config directory %s: %s", dir, err.Error())
		}
	}

	// initial config.yaml
	if _, err := os.Stat(C.Path.Config()); os.IsNotExist(err) {
		log.Infoln("Can't find config, create a initial config file")
		f, err := os.OpenFile(C.Path.Config(), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("can't create file %s: %s", C.Path.Config(), err.Error())
		}
		f.Write([]byte(`mixed-port: 7890`))
		f.Close()
	}

	// initial GeoIP
	if err := initGeoIP(); err != nil {
		return fmt.Errorf("can't initial GeoIP: %w", err)
	}

	return nil
}
