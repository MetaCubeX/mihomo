package mmdb

import (
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

var overrideMmdb *geoip2.Reader

func InstallOverride(override *geoip2.Reader) {
	overrideMmdb = overrideMmdb
}

func Instance() Reader {
	once.Do(func() {
		mmdb, err := maxminddb.Open(C.Path.MMDB())
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
		reader = Reader{Reader: mmdb}
		if mmdb.Metadata.DatabaseType == "sing-geoip" {
			reader.databaseType = typeSing
		} else {
			reader.databaseType = typeMaxmind
		}
	})

	return reader
}
