package mmdb

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

type geoip2Country struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type Reader struct {
	*maxminddb.Reader
	databaseType
}

func (r Reader) LookupCode(ipAddress net.IP) string {
	switch r.databaseType {
	case typeMaxmind:
		var country geoip2Country
		_ = r.Lookup(ipAddress, &country)
		return country.Country.IsoCode

	case typeSing:
		var code string
		_ = r.Lookup(ipAddress, &code)
		return code

	default:
		panic(fmt.Sprint("unknown geoip database type:", r.databaseType))
	}
}
