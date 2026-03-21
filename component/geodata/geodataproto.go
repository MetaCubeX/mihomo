package geodata

import (
	"github.com/metacubex/mihomo/component/geodata/router"
)

type LoaderImplementation interface {
	LoadSiteByPath(filename, list string) ([]*router.Domain, error)
	LoadSiteByBytes(geositeBytes []byte, list string) ([]*router.Domain, error)
	LoadIPByPath(filename, country string) ([]*router.CIDR, error)
	LoadIPByBytes(geoipBytes []byte, country string) ([]*router.CIDR, error)
}

type Loader interface {
	LoaderImplementation
	LoadGeoSite(list string) ([]*router.Domain, error)
	LoadGeoIP(country string) ([]*router.CIDR, error)
}
