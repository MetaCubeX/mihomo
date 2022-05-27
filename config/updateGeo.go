package config

import (
	"fmt"
	"github.com/Dreamacro/clash/component/geodata"
	_ "github.com/Dreamacro/clash/component/geodata/standard"
	C "github.com/Dreamacro/clash/constant"
	"github.com/oschwald/geoip2-golang"
	"os"
	"runtime"
)

func UpdateGeoDatabases() error {
	var (
		tmpMMDB    = C.Path.Resolve("temp_country.mmdb")
		tmpGepIP   = C.Path.Resolve("temp_geoip.dat")
		tmpGeoSite = C.Path.Resolve("temp_geosite.dat")
	)

	if C.GeodataMode {
		if err := downloadGeoIP(tmpGepIP); err != nil {
			return fmt.Errorf("can't download GeoIP database file: %w", err)
		}

		if err := verifyGeoSite("temp_geoip.dat"); err != nil {
			_ = os.Remove(tmpGepIP)
			return fmt.Errorf("invalid GeoIP database file: %s", err)
		}

		if err := os.Rename(tmpGepIP, C.Path.GeoIP()); err != nil {
			return fmt.Errorf("can't rename MMDB database file: %w", err)
		}

	} else {
		if err := downloadMMDB(tmpMMDB); err != nil {
			return fmt.Errorf("can't download MMDB database file: %w", err)
		}

		if err := verifyMMDB("temp_country.mmdb"); err != nil {
			_ = os.Remove(tmpMMDB)
			return fmt.Errorf("invalid MMDB database file: %s", err)
		}

		if err := os.Rename(tmpMMDB, C.Path.MMDB()); err != nil {
			return fmt.Errorf("can't rename MMDB database file: %w", err)
		}
	}

	if err := downloadGeoSite(tmpGeoSite); err != nil {
		return fmt.Errorf("can't download GeoSite database file: %w", err)
	}

	if err := verifyGeoSite("temp_geosite.dat"); err != nil {
		_ = os.Remove(tmpGeoSite)
		return fmt.Errorf("invalid GeoSite database file: %s", err)
	}

	if err := os.Rename(tmpGeoSite, C.Path.GeoSite()); err != nil {
		return fmt.Errorf("can't rename GeoSite database file: %w", err)
	}
	runtime.GC()
	return nil
}

func verifyMMDB(path string) error {
	instance, err := geoip2.Open(path)
	if err == nil {
		_ = instance.Close()
	}
	return err
}

func verifyGeoSite(path string) error {
	geoLoader, err := geodata.GetGeoDataLoader("standard")
	if err != nil {
		return err
	}

	_, err = geoLoader.LoadSite(path, "cn")

	return err
}
