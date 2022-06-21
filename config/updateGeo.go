package config

import (
	"fmt"
	"github.com/Dreamacro/clash/component/geodata"
	_ "github.com/Dreamacro/clash/component/geodata/standard"
	C "github.com/Dreamacro/clash/constant"
	"github.com/oschwald/geoip2-golang"
	"io/ioutil"
	"net/http"
	"runtime"
)

func UpdateGeoDatabases() error {
	defer runtime.GC()
	geoLoader, err := geodata.GetGeoDataLoader("standard")
	if err != nil {
		return err
	}

	if C.GeodataMode {
		data, err := downloadForBytes(C.GeoIpUrl)
		if err != nil {
			return fmt.Errorf("can't download GeoIP database file: %w", err)
		}

		if _, err = geoLoader.LoadIPByBytes(data, "cn"); err != nil {
			return fmt.Errorf("invalid GeoIP database file: %s", err)
		}

		if saveFile(data, C.Path.GeoIP()) != nil {
			return fmt.Errorf("can't save GeoIP database file: %w", err)
		}

	} else {
		data, err := downloadForBytes(C.MmdbUrl)
		if err != nil {
			return fmt.Errorf("can't download MMDB database file: %w", err)
		}

		instance, err := geoip2.FromBytes(data)
		if err != nil {
			return fmt.Errorf("invalid MMDB database file: %s", err)
		}
		_ = instance.Close()

		if saveFile(data, C.Path.MMDB()) != nil {
			return fmt.Errorf("can't save MMDB database file: %w", err)
		}
	}

	data, err := downloadForBytes(C.GeoSiteUrl)
	if err != nil {
		return fmt.Errorf("can't download GeoSite database file: %w", err)
	}

	if _, err = geoLoader.LoadSiteByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoSite database file: %s", err)
	}

	if saveFile(data, C.Path.GeoSite()) != nil {
		return fmt.Errorf("can't save GeoSite database file: %w", err)
	}

	return nil
}

func downloadForBytes(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

func saveFile(bytes []byte, path string) error {
	return ioutil.WriteFile(path, bytes, 0o644)
}
