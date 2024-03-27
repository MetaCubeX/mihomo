//go:build android && cmfa

package mmdb

import "github.com/oschwald/maxminddb-golang"

func InstallOverride(override *maxminddb.Reader) {
	newReader := IPReader{Reader: override}
	switch override.Metadata.DatabaseType {
	case "sing-geoip":
		IPreader.databaseType = typeSing
	case "Meta-geoip0":
		IPreader.databaseType = typeMetaV0
	default:
		IPreader.databaseType = typeMaxmind
	}
	IPreader = newReader
}
