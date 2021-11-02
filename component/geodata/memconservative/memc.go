package memconservative

import (
	"fmt"
	"runtime"

	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
)

type memConservativeLoader struct {
	geoipcache   GeoIPCache
	geositecache GeoSiteCache
}

func (m *memConservativeLoader) LoadIP(filename, country string) ([]*router.CIDR, error) {
	defer runtime.GC()
	geoip, err := m.geoipcache.Unmarshal(filename, country)
	if err != nil {
		return nil, fmt.Errorf("failed to decode geodata file: %s, base error: %s", filename, err.Error())
	}
	return geoip.Cidr, nil
}

func (m *memConservativeLoader) LoadSite(filename, list string) ([]*router.Domain, error) {
	defer runtime.GC()
	geosite, err := m.geositecache.Unmarshal(filename, list)
	if err != nil {
		return nil, fmt.Errorf("failed to decode geodata file: %s, base error: %s", filename, err.Error())
	}
	return geosite.Domain, nil
}

func newMemConservativeLoader() geodata.LoaderImplementation {
	return &memConservativeLoader{make(map[string]*router.GeoIP), make(map[string]*router.GeoSite)}
}

func init() {
	geodata.RegisterGeoDataLoaderImplementationCreator("memconservative", newMemConservativeLoader)
}
