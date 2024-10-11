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
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
)

var (
	autoUpdate     bool
	updateInterval int

	updatingGeo atomic.Bool
)

func GeoAutoUpdate() bool {
	return autoUpdate
}

func GeoUpdateInterval() int {
	return updateInterval
}

func SetGeoAutoUpdate(newAutoUpdate bool) {
	autoUpdate = newAutoUpdate
}

func SetGeoUpdateInterval(newGeoUpdateInterval int) {
	updateInterval = newGeoUpdateInterval
}

func UpdateMMDB() (err error) {
	vehicle := resource.NewHTTPVehicle(geodata.MmdbUrl(), C.Path.MMDB(), "", nil, defaultHttpTimeout)
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		return fmt.Errorf("can't download MMDB database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download MMDB database file: no data")
	}

	instance, err := maxminddb.FromBytes(data)
	if err != nil {
		return fmt.Errorf("invalid MMDB database file: %s", err)
	}
	_ = instance.Close()

	defer mmdb.ReloadIP()
	mmdb.IPInstance().Reader.Close() //  mmdb is loaded with mmap, so it needs to be closed before overwriting the file
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save MMDB database file: %w", err)
	}
	return nil
}

func UpdateASN() (err error) {
	vehicle := resource.NewHTTPVehicle(geodata.ASNUrl(), C.Path.ASN(), "", nil, defaultHttpTimeout)
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		return fmt.Errorf("can't download ASN database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download ASN database file: no data")
	}

	instance, err := maxminddb.FromBytes(data)
	if err != nil {
		return fmt.Errorf("invalid ASN database file: %s", err)
	}
	_ = instance.Close()

	defer mmdb.ReloadASN()
	mmdb.ASNInstance().Reader.Close() //  mmdb is loaded with mmap, so it needs to be closed before overwriting the file
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save ASN database file: %w", err)
	}
	return nil
}

func UpdateGeoIp() (err error) {
	geoLoader, err := geodata.GetGeoDataLoader("standard")

	vehicle := resource.NewHTTPVehicle(geodata.GeoIpUrl(), C.Path.GeoIP(), "", nil, defaultHttpTimeout)
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		return fmt.Errorf("can't download GeoIP database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download GeoIP database file: no data")
	}

	if _, err = geoLoader.LoadIPByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoIP database file: %s", err)
	}

	defer geodata.ClearGeoIPCache()
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save GeoIP database file: %w", err)
	}
	return nil
}

func UpdateGeoSite() (err error) {
	geoLoader, err := geodata.GetGeoDataLoader("standard")

	vehicle := resource.NewHTTPVehicle(geodata.GeoSiteUrl(), C.Path.GeoSite(), "", nil, defaultHttpTimeout)
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		return fmt.Errorf("can't download GeoSite database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download GeoSite database file: no data")
	}

	if _, err = geoLoader.LoadSiteByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoSite database file: %s", err)
	}

	defer geodata.ClearGeoSiteCache()
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save GeoSite database file: %w", err)
	}
	return nil
}

func updateGeoDatabases() error {
	defer runtime.GC()

	b, _ := batch.New[interface{}](context.Background())

	if geodata.GeoIpEnable() {
		if geodata.GeodataMode() {
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
	}

	if geodata.ASNEnable() {
		b.Go("UpdateASN", func() (_ interface{}, err error) {
			err = UpdateASN()
			return
		})
	}

	if geodata.GeoSiteEnable() {
		b.Go("UpdateGeoSite", func() (_ interface{}, err error) {
			err = UpdateGeoSite()
			return
		})
	}

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
	filesToCheck := []string{
		C.Path.GeoIP(),
		C.Path.MMDB(),
		C.Path.ASN(),
		C.Path.GeoSite(),
	}

	for _, file := range filesToCheck {
		var fileInfo os.FileInfo
		fileInfo, err = os.Stat(file)
		if err == nil {
			return nil, fileInfo.ModTime()
		}
	}

	return
}

func RegisterGeoUpdater() {
	if updateInterval <= 0 {
		log.Errorln("[GEO] Invalid update interval: %d", updateInterval)
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(updateInterval) * time.Hour)
		defer ticker.Stop()

		err, lastUpdate := getUpdateTime()
		if err != nil {
			log.Errorln("[GEO] Get GEO database update time error: %s", err.Error())
			return
		}

		log.Infoln("[GEO] last update time %s", lastUpdate)
		if lastUpdate.Add(time.Duration(updateInterval) * time.Hour).Before(time.Now()) {
			log.Infoln("[GEO] Database has not been updated for %v, update now", time.Duration(updateInterval)*time.Hour)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				return
			}
		}

		for range ticker.C {
			log.Infoln("[GEO] updating database every %d hours", updateInterval)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
			}
		}
	}()
}
