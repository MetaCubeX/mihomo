package common

import (
	"fmt"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/memconservative"
	"github.com/metacubex/mihomo/component/geodata/router"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type GEOSITE struct {
	Base
	country    string
	adapter    string
	recodeSize int
	matcher    atomic.Pointer[geoSiteMatcherRef]
}

// Retain the matcher, not its cache generation: a live rule must not keep
// retired raw categories and unrelated matchers alive after a reload.
type geoSiteMatcherRef struct {
	generation uint64
	matcher    router.DomainMatcher
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
	return gs.country
}

func (gs *GEOSITE) GetDomainMatcher() (router.DomainMatcher, error) {
	if ref := gs.matcher.Load(); ref != nil && ref.generation == geodata.GeoSiteCacheGeneration() {
		return ref.matcher, nil
	}
	matcher, generation, err := geodata.LoadGeoSiteMatcherWithGeneration(gs.country)
	if err != nil {
		return nil, fmt.Errorf("load GeoSite data error, %w", err)
	}
	gs.matcher.Store(&geoSiteMatcherRef{generation: generation, matcher: matcher})
	return matcher, nil
}

func (gs *GEOSITE) GetRecodeSize() int {
	if matcher, err := gs.GetDomainMatcher(); err == nil {
		return matcher.Count()
	}
	return 0
}

func NewGEOSITE(country string, adapter string) (*GEOSITE, error) {
	if err := geodata.InitGeoSite(); err != nil {
		log.Errorln("can't initial GeoSite: %s", err)
		return nil, err
	}

	geoSite := &GEOSITE{
		Base:    Base{},
		country: country,
		adapter: adapter,
	}

	matcher, err := geoSite.GetDomainMatcher() // test load
	if err != nil {
		return nil, err
	}

	log.Infoln("Finished initial GeoSite rule %s => %s, records: %d", country, adapter, matcher.Count())

	return geoSite, nil
}

var _ C.Rule = (*GEOSITE)(nil)
