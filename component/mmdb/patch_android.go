//go:build android && cmfa

package mmdb

import "github.com/oschwald/maxminddb-golang"

func InstallOverride(override *maxminddb.Reader) {
	newReader := Reader{Reader: override}
	switch override.Metadata.DatabaseType {
	case "sing-geoip":
		reader.databaseType = typeSing
	case "Meta-geoip0":
		reader.databaseType = typeMetaV0
	default:
		reader.databaseType = typeMaxmind
	}
	reader = newReader
}
