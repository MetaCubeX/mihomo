package rules

import (
	"fmt"

	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	_ "github.com/Dreamacro/clash/component/geodata/standard"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type GEOSITE struct {
	country   string
	adapter   string
	ruleExtra *C.RuleExtra
	matcher   *router.DomainMatcher
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

func (gs *GEOSITE) RuleExtra() *C.RuleExtra {
	return gs.ruleExtra
}

func NewGEOSITE(country string, adapter string, ruleExtra *C.RuleExtra) (*GEOSITE, error) {
	geoLoaderName := "standard"
	geoLoader, err := geodata.GetGeoDataLoader(geoLoaderName)
	if err != nil {
		return nil, fmt.Errorf("load GeoSite data error, %s", err.Error())
	}

	domains, err := geoLoader.LoadGeoSite(country)
	if err != nil {
		return nil, fmt.Errorf("load GeoSite data error, %s", err.Error())
	}

	/**
	linear: linear algorithm
	matcher, err := router.NewDomainMatcher(domains)
	mph：minimal perfect hash algorithm
	*/
	matcher, err := router.NewMphMatcherGroup(domains)
	if err != nil {
		return nil, fmt.Errorf("load GeoSite data error, %s", err.Error())
	}

	log.Infoln("Start initial GeoSite rule %s => %s, records: %d", country, adapter, len(domains))

	geoSite := &GEOSITE{
		country:   country,
		adapter:   adapter,
		ruleExtra: ruleExtra,
		matcher:   matcher,
	}

	return geoSite, nil
}
