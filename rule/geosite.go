package rules

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/rule/geodata"
	//_ "github.com/Dreamacro/clash/rule/geodata/memconservative"
	"github.com/Dreamacro/clash/rule/geodata/router"
	_ "github.com/Dreamacro/clash/rule/geodata/standard"
)

type GEOSITE struct {
	country string
	adapter string
	network C.NetWork
	matcher *router.DomainMatcher
}

func (gs *GEOSITE) RuleType() C.RuleType {
	return C.GEOSITE
}

func (gs *GEOSITE) Match(metadata *C.Metadata) bool {
	if metadata.AddrType != C.AtypDomainName {
		return false
	}

	domain := metadata.Host
	return gs.matcher.ApplyDomain(domain)
}

func (gs *GEOSITE) Adapter() string {
	return gs.adapter
}

func (gs *GEOSITE) Payload() string {
	return gs.country
}

func (gs *GEOSITE) ShouldResolveIP() bool {
	return false
}

func (gs *GEOSITE) NetWork() C.NetWork {
	return gs.network
}

func NewGEOSITE(country string, adapter string, network C.NetWork) (*GEOSITE, error) {
	geoLoaderName := "standard"
	//geoLoaderName := "memconservative"
	geoLoader, err := geodata.GetGeoDataLoader(geoLoaderName)
	if err != nil {
		return nil, fmt.Errorf("[GeoSite] %s", err.Error())
	}

	domains, err := geoLoader.LoadGeoSite(country)
	if err != nil {
		return nil, fmt.Errorf("[GeoSite] %s", err.Error())
	}

	//linear: linear algorithm
	//matcher, err := router.NewDomainMatcher(domains)

	//mph：minimal perfect hash algorithm
	matcher, err := router.NewMphMatcherGroup(domains)
	if err != nil {
		return nil, fmt.Errorf("[GeoSite] %s", err.Error())
	}

	log.Infoln("Start initial GeoSite rule %s => %s, records: %d", country, adapter, len(domains))

	geoSite := &GEOSITE{
		country: country,
		adapter: adapter,
		network: network,
		matcher: matcher,
	}

	return geoSite, nil
}
