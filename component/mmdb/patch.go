package mmdb

import (
	"github.com/oschwald/geoip2-golang"
)

var overrideMmdb *geoip2.Reader

func InstallOverride(override *geoip2.Reader) {
	overrideMmdb = overrideMmdb
}

func Instance() *geoip2.Reader {
	if override := overrideMmdb; override != nil {
		return override
	}

	return DefaultInstance()
}
