//go:build android && cmfa

package mmdb

import "github.com/oschwald/maxminddb-golang"

func InstallOverride(override *maxminddb.Reader) {
	newReader := IPReader{Reader: override}
	switch override.Metadata.DatabaseType {
	case "sing-geoip":
		ipReader.databaseType = typeSing
	case "Meta-geoip0":
		ipReader.databaseType = typeMetaV0
	default:
		ipReader.databaseType = typeMaxmind
	}
	ipReader = newReader
}
