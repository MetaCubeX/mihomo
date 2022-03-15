package common

import (
	"fmt"

	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	_ "github.com/Dreamacro/clash/component/geodata/memconservative"
	_ "github.com/Dreamacro/clash/component/geodata/standard"
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

func (gs *GEOSITE) ShouldFindProcess() bool {
	return false
}

func (gs *GEOSITE) RuleExtra() *C.RuleExtra {
	return gs.ruleExtra
}

func (gs *GEOSITE) GetDomainMatcher() *router.DomainMatcher {
	return gs.matcher
}

func NewGEOSITE(country string, adapter string, ruleExtra *C.RuleExtra) (*GEOSITE, error) {
	matcher, recordsCount, err := geodata.LoadGeoSiteMatcher(country)
	if err != nil {
		return nil, fmt.Errorf("load GeoSite data error, %s", err.Error())
	}

	log.Infoln("Start initial GeoSite rule %s => %s, records: %d", country, adapter, recordsCount)

	geoSite := &GEOSITE{
		country:   country,
		adapter:   adapter,
		ruleExtra: ruleExtra,
		matcher:   matcher,
	}

	return geoSite, nil
}
