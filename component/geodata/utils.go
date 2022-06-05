package geodata

import (
	"github.com/Dreamacro/clash/component/geodata/router"

	"golang.org/x/exp/maps"
)

func loadGeoSiteMatcher(countryCode string) (*router.DomainMatcher, int, error) {
	geoLoaderName := "standard"
	geoLoader, err := GetGeoDataLoader(geoLoaderName)
	if err != nil {
		return nil, 0, err
	}

	domains, err := geoLoader.LoadGeoSite(countryCode)
	if err != nil {
		return nil, 0, err
	}

	/**
	linear: linear algorithm
	matcher, err := router.NewDomainMatcher(domains)
	mph：minimal perfect hash algorithm
	*/
	matcher, err := router.NewMphMatcherGroup(domains)
	if err != nil {
		return nil, 0, err
	}

	return matcher, len(domains), nil
}

var ruleProviders = make(map[string]*router.DomainMatcher)

// HasProvider has geo site provider by county code
func HasProvider(countyCode string) (ok bool) {
	_, ok = ruleProviders[countyCode]
	return ok
}

// GetProvidersList get geo site providers
func GetProvidersList(countyCode string) []*router.DomainMatcher {
	return maps.Values(ruleProviders)
}

// GetProviderByCode get geo site provider by county code
func GetProviderByCode(countyCode string) (matcher *router.DomainMatcher, ok bool) {
	matcher, ok = ruleProviders[countyCode]
	return
}

func LoadProviderByCode(countyCode string) (matcher *router.DomainMatcher, count int, err error) {
	var ok bool
	matcher, ok = ruleProviders[countyCode]
	if !ok {
		if matcher, count, err = loadGeoSiteMatcher(countyCode); err == nil {
			ruleProviders[countyCode] = matcher
		}
	}
	return
}
