package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/batch"
	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
)

var (
	updatingGeo atomic.Bool
)

func UpdateMMDB() (err error) {
	defer mmdb.ReloadIP()
	data, err := downloadForBytes(C.MmdbUrl)
	if err != nil {
		return fmt.Errorf("can't download MMDB database file: %w", err)
	}
	instance, err := maxminddb.FromBytes(data)
	if err != nil {
		return fmt.Errorf("invalid MMDB database file: %s", err)
	}
	_ = instance.Close()

	mmdb.IPInstance().Reader.Close() //  mmdb is loaded with mmap, so it needs to be closed before overwriting the file
	if err = saveFile(data, C.Path.MMDB()); err != nil {
		return fmt.Errorf("can't save MMDB database file: %w", err)
	}
	return nil
}

func UpdateASN() (err error) {
	defer mmdb.ReloadASN()
	data, err := downloadForBytes(C.ASNUrl)
	if err != nil {
		return fmt.Errorf("can't download ASN database file: %w", err)
	}

	instance, err := maxminddb.FromBytes(data)
	if err != nil {
		return fmt.Errorf("invalid ASN database file: %s", err)
	}
	_ = instance.Close()

	mmdb.ASNInstance().Reader.Close() //  mmdb is loaded with mmap, so it needs to be closed before overwriting the file
	if err = saveFile(data, C.Path.ASN()); err != nil {
		return fmt.Errorf("can't save ASN database file: %w", err)
	}
	return nil
}

func UpdateGeoIp() (err error) {
	defer geodata.ClearGeoIPCache()
	geoLoader, err := geodata.GetGeoDataLoader("standard")
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
	return nil
}

func UpdateGeoSite() (err error) {
	defer geodata.ClearGeoSiteCache()
	geoLoader, err := geodata.GetGeoDataLoader("standard")
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
	return nil
}

func updateGeoDatabases() error {
	defer runtime.GC()

	b, _ := batch.New[interface{}](context.Background())

	if C.GeodataMode {
		b.Go("UpdateGeoIp", func() (_ interface{}, err error) {
			err = UpdateGeoIp()
			return
		})
	} else {
		b.Go("UpdateMMDB", func() (_ interface{}, err error) {
			err = UpdateMMDB()
			return
		})
	}

	if C.ASNEnable {
		b.Go("UpdateASN", func() (_ interface{}, err error) {
			err = UpdateASN()
			return
		})
	}

	b.Go("UpdateGeoSite", func() (_ interface{}, err error) {
		err = UpdateGeoSite()
		return
	})

	if e := b.Wait(); e != nil {
		return e.Err
	}

	return nil
}

var ErrGetDatabaseUpdateSkip = errors.New("GEO database is updating, skip")

func UpdateGeoDatabases() error {
	log.Infoln("[GEO] Start updating GEO database")

	if updatingGeo.Load() {
		return ErrGetDatabaseUpdateSkip
	}

	updatingGeo.Store(true)
	defer updatingGeo.Store(false)

	log.Infoln("[GEO] Updating GEO database")

	if err := updateGeoDatabases(); err != nil {
		log.Errorln("[GEO] update GEO database error: %s", err.Error())
		return err
	}

	return nil
}

func getUpdateTime() (err error, time time.Time) {
	var fileInfo os.FileInfo
	if C.GeodataMode {
		fileInfo, err = os.Stat(C.Path.GeoIP())
		if err != nil {
			return err, time
		}
	} else {
		fileInfo, err = os.Stat(C.Path.MMDB())
		if err != nil {
			return err, time
		}
	}

	return nil, fileInfo.ModTime()
}

func RegisterGeoUpdater() {
	if C.GeoUpdateInterval <= 0 {
		log.Errorln("[GEO] Invalid update interval: %d", C.GeoUpdateInterval)
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(C.GeoUpdateInterval) * time.Hour)
		defer ticker.Stop()

		err, lastUpdate := getUpdateTime()
		if err != nil {
			log.Errorln("[GEO] Get GEO database update time error: %s", err.Error())
			return
		}

		log.Infoln("[GEO] last update time %s", lastUpdate)
		if lastUpdate.Add(time.Duration(C.GeoUpdateInterval) * time.Hour).Before(time.Now()) {
			log.Infoln("[GEO] Database has not been updated for %v, update now", time.Duration(C.GeoUpdateInterval)*time.Hour)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				return
			}
		}

		for range ticker.C {
			log.Infoln("[GEO] updating database every %d hours", C.GeoUpdateInterval)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
			}
		}
	}()
}
