package config

import (
	"fmt"
	"runtime"

	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"

	"github.com/oschwald/maxminddb-golang"
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

		if err = saveFile(data, C.Path.GeoIP()); err != nil {
			return fmt.Errorf("can't save GeoIP database file: %w", err)
		}

	} else {
		defer mmdb.Reload()
		data, err := downloadForBytes(C.MmdbUrl)
		if err != nil {
			return fmt.Errorf("can't download MMDB database file: %w", err)
		}

		instance, err := maxminddb.FromBytes(data)
		if err != nil {
			return fmt.Errorf("invalid MMDB database file: %s", err)
		}
		_ = instance.Close()

		mmdb.Instance().Reader.Close() //  mmdb is loaded with mmap, so it needs to be closed before overwriting the file
		if err = saveFile(data, C.Path.MMDB()); err != nil {
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

	if err = saveFile(data, C.Path.GeoSite()); err != nil {
		return fmt.Errorf("can't save GeoSite database file: %w", err)
	}

	geodata.ClearCache()

	return nil
}
