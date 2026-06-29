package common

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/memconservative"
	"github.com/metacubex/mihomo/component/geodata/router"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type GEOSITE struct {
	Base
	countries  []string
	payload    string
	adapter    string
	recodeSize int
}

type multiGeoSiteMatcher []router.DomainMatcher

func (m multiGeoSiteMatcher) ApplyDomain(domain string) bool {
	for _, matcher := range m {
		if matcher.ApplyDomain(domain) {
			return true
		}
	}
	return false
}

func (m multiGeoSiteMatcher) Count() int {
	count := 0
	for _, matcher := range m {
		count += matcher.Count()
	}
	return count
}

func (gs *GEOSITE) RuleType() C.RuleType {
	return C.GEOSITE
}

func (gs *GEOSITE) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	return gs.MatchDomain(metadata.RuleHost()), gs.adapter
}

// MatchDomain implements C.DomainMatcher
func (gs *GEOSITE) MatchDomain(domain string) bool {
	if len(domain) == 0 {
		return false
	}
	matcher, err := gs.GetDomainMatcher()
	if err != nil {
		return false
	}
	return matcher.ApplyDomain(domain)
}

func (gs *GEOSITE) Adapter() string {
	return gs.adapter
}

func (gs *GEOSITE) Payload() string {
	return gs.payload
}

func (gs *GEOSITE) GetDomainMatcher() (router.DomainMatcher, error) {
	return gs.loadDomainMatcher()
}

func (gs *GEOSITE) loadDomainMatcher() (router.DomainMatcher, error) {
	matchers := make(multiGeoSiteMatcher, 0, len(gs.countries))
	for _, country := range gs.countries {
		matcher, err := geodata.LoadGeoSiteMatcher(country)
		if err != nil {
			return nil, fmt.Errorf("load GeoSite data error, %w", err)
		}
		matchers = append(matchers, matcher)
	}

	switch len(matchers) {
	case 0:
		return nil, fmt.Errorf("load GeoSite data error, empty matcher list")
	case 1:
		return matchers[0], nil
	default:
		return matchers, nil
	}
}

func (gs *GEOSITE) GetRecodeSize() int {
	if matcher, err := gs.GetDomainMatcher(); err == nil {
		return matcher.Count()
	}
	return 0
}

func NewGEOSITE(country string, adapter string) (*GEOSITE, error) {
	countries, err := parseSlashSeparatedPayload(country, "geosite country", strings.ToLower)
	if err != nil {
		return nil, err
	}

	if err := geodata.InitGeoSite(); err != nil {
		log.Errorln("can't initial GeoSite: %s", err)
		return nil, err
	}

	geoSite := &GEOSITE{
		Base:      Base{},
		countries: countries,
		payload:   strings.Join(countries, "/"),
		adapter:   adapter,
	}

	matcher, err := geoSite.loadDomainMatcher() // test load
	if err != nil {
		return nil, err
	}

	log.Infoln("Finished initial GeoSite rule %s => %s, records: %d", geoSite.payload, adapter, matcher.Count())

	return geoSite, nil
}

var _ C.Rule = (*GEOSITE)(nil)
