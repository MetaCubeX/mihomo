package updater

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
)

var (
	UpdatingGeo atomic.Bool
)

func updateGeoDatabases() error {
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
	}

	if C.ASNEnable {
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

		mmdb.ASNInstance().Reader.Close()
		if err = saveFile(data, C.Path.ASN()); err != nil {
			return fmt.Errorf("can't save ASN database file: %w", err)
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

var ErrGetDatabaseUpdateSkip = errors.New("GEO database is updating, skip")

func UpdateGeoDatabases() error {
	log.Infoln("[GEO] Start updating GEO database")

	if UpdatingGeo.Load() {
		return ErrGetDatabaseUpdateSkip
	}

	UpdatingGeo.Store(true)
	defer UpdatingGeo.Store(false)

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
