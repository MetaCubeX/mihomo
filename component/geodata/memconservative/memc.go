package memconservative

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
)

type memConservativeLoader struct {
	geoipcache   GeoIPCache
	geositecache GeoSiteCache
}

func (m *memConservativeLoader) LoadIPByPath(filename, country string) ([]*router.CIDR, error) {
	defer runtime.GC()
	geoip, err := m.geoipcache.Unmarshal(filename, country)
	if err != nil {
		return nil, fmt.Errorf("failed to decode geodata file: %s, base error: %s", filename, err.Error())
	}
	return geoip.Cidr, nil
}

func (m *memConservativeLoader) LoadIPByBytes(geoipBytes []byte, country string) ([]*router.CIDR, error) {
	return nil, errors.New("memConservative do not support LoadIPByBytes")
}

func (m *memConservativeLoader) LoadSiteByPath(filename, list string) ([]*router.Domain, error) {
	defer runtime.GC()
	geosite, err := m.geositecache.Unmarshal(filename, list)
	if err != nil {
		return nil, fmt.Errorf("failed to decode geodata file: %s, base error: %s", filename, err.Error())
	}
	return geosite.Domain, nil
}

func (m *memConservativeLoader) LoadSiteByBytes(geositeBytes []byte, list string) ([]*router.Domain, error) {
	return nil, errors.New("memConservative do not support LoadSiteByBytes")
}

func newMemConservativeLoader() geodata.LoaderImplementation {
	return &memConservativeLoader{make(map[string]*router.GeoIP), make(map[string]*router.GeoSite)}
}

func init() {
	geodata.RegisterGeoDataLoaderImplementationCreator("memconservative", newMemConservativeLoader)
}
