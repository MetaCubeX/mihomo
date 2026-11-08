package geodata

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var (
	geoSettingsMu  sync.Mutex
	geoMode        bool
	geoLoaderName  = "memconservative"
	geoSiteMatcher = "succinct"
)

//  geoLoaderName = "standard"

func GeodataMode() bool {
	return geoMode
}

func LoaderName() string {
	geoSettingsMu.Lock()
	defer geoSettingsMu.Unlock()
	return geoLoaderName
}

func SiteMatcherName() string {
	geoSettingsMu.Lock()
	defer geoSettingsMu.Unlock()
	return geoSiteMatcher
}

func SetGeodataMode(newGeodataMode bool) {
	geoMode = newGeodataMode
}

func SetLoader(newLoader string) {
	if newLoader == "memc" {
		newLoader = "memconservative"
	}
	geoSettingsMu.Lock()
	defer geoSettingsMu.Unlock()
	geoLoaderName = newLoader
}

func SetSiteMatcher(newMatcher string) {
	geoSettingsMu.Lock()
	defer geoSettingsMu.Unlock()
	switch newMatcher {
	case "mph", "hybrid":
		geoSiteMatcher = "mph"
	default:
		geoSiteMatcher = "succinct"
	}
}

func Verify(name string) error {
	switch name {
	case C.GeositeName:
		_, err := LoadGeoSiteMatcher("CN")
		return err
	case C.GeoipName:
		_, err := LoadGeoIPMatcher("CN")
		return err
	default:
		return fmt.Errorf("not support name")
	}
}

// A generation owns its successful results and in-flight builds. Old builds
// can finish after ClearGeoSiteCache but cannot populate the new generation.
// Settings retain their existing temporary-parse contract; only an explicit
// cache clear advances the generation.
type geoSiteCache struct {
	generation   uint64
	mu           sync.Mutex
	domains      map[string][]*router.Domain
	matchers     map[string]router.DomainMatcher
	rawGroup     singleflight.Group[[]*router.Domain]
	matcherGroup singleflight.Group[router.DomainMatcher]
}

func newGeoSiteCache(generation uint64) *geoSiteCache {
	return &geoSiteCache{generation: generation, domains: make(map[string][]*router.Domain), matchers: make(map[string]router.DomainMatcher)}
}

var geoSiteState atomic.Pointer[geoSiteCache]

func init() {
	geoSiteState.Store(newGeoSiteCache(1))
}

// GeoSiteCacheGeneration changes only when ClearGeoSiteCache is called.
func GeoSiteCacheGeneration() uint64 {
	return geoSiteState.Load().generation
}

func (s *geoSiteCache) loadDomains(listName string) ([]*router.Domain, error) {
	s.mu.Lock()
	domains, ok := s.domains[listName]
	s.mu.Unlock()
	if ok {
		return domains, nil
	}
	domains, err, _ := s.rawGroup.Do(listName, func() ([]*router.Domain, error) {
		s.mu.Lock()
		domains, ok := s.domains[listName]
		s.mu.Unlock()
		if ok {
			return domains, nil
		}
		loader, err := GetGeoDataLoader(LoaderName())
		if err != nil {
			return nil, err
		}
		domains, err = loader.LoadGeoSite(listName)
		if err == nil {
			s.mu.Lock()
			s.domains[listName] = domains
			s.mu.Unlock()
		}
		return domains, err
	})
	return domains, err
}

func LoadGeoSiteMatcher(countryCode string) (router.DomainMatcher, error) {
	matcher, _, err := LoadGeoSiteMatcherWithGeneration(countryCode)
	return matcher, err
}

// LoadGeoSiteMatcherWithGeneration returns the generation actually used,
// including when a clear races an in-flight build.
func LoadGeoSiteMatcherWithGeneration(countryCode string) (router.DomainMatcher, uint64, error) {
	state := geoSiteState.Load()
	if countryCode == "" {
		return nil, state.generation, fmt.Errorf("country code could not be empty")
	}

	not := false
	if countryCode[0] == '!' {
		not = true
		countryCode = countryCode[1:]
		if countryCode == "" {
			return nil, state.generation, fmt.Errorf("country code could not be empty")
		}
	}
	countryCode = strings.ToLower(countryCode)

	parts := strings.Split(countryCode, "@")
	listName := strings.TrimSpace(parts[0])
	attrVal := parts[1:]
	attrs := parseAttrs(attrVal)

	if listName == "" {
		return nil, state.generation, fmt.Errorf("empty listname in rule: %s", countryCode)
	}

	matcherName := listName
	if !attrs.IsEmpty() {
		matcherName += "@" + attrs.String()
	}
	state.mu.Lock()
	matcher, cached := state.matchers[matcherName]
	state.mu.Unlock()
	var err error
	if !cached {
		matcher, err, _ = state.matcherGroup.Do(matcherName, func() (router.DomainMatcher, error) {
			state.mu.Lock()
			matcher, cached := state.matchers[matcherName]
			state.mu.Unlock()
			if cached {
				return matcher, nil
			}
			log.Infoln("Load GeoSite rule: %s", matcherName)
			domains, err := state.loadDomains(listName)
			if err != nil {
				return nil, err
			}

			if attrs.IsEmpty() {
				if strings.Contains(countryCode, "@") {
					log.Warnln("empty attribute list: %s", countryCode)
				}
			} else {
				filteredDomains := make([]*router.Domain, 0, len(domains))
				hasAttrMatched := false
				for _, domain := range domains {
					if attrs.Match(domain) {
						hasAttrMatched = true
						filteredDomains = append(filteredDomains, domain)
					}
				}
				if !hasAttrMatched {
					log.Warnln("attribute match no rule: geosite: %s", countryCode)
				}
				domains = filteredDomains
			}

			/**
			linear: linear algorithm
			matcher, err := router.NewDomainMatcher(domains)
			mph：minimal perfect hash algorithm
			*/
			if SiteMatcherName() == "mph" {
				matcher, err = router.NewMphMatcherGroup(domains)
			} else {
				matcher, err = router.NewSuccinctMatcherGroup(domains)
			}
			if err == nil {
				state.mu.Lock()
				state.matchers[matcherName] = matcher
				state.mu.Unlock()
			}
			return matcher, err
		})
	}
	if err != nil {
		return nil, state.generation, err
	}

	if not {
		matcher = router.NewNotDomainMatcherGroup(matcher)
	}

	return matcher, state.generation, nil
}

var loadGeoIPMatcherSF = singleflight.Group[router.IPMatcher]{StoreResult: true}

func LoadGeoIPMatcher(country string) (router.IPMatcher, error) {
	if len(country) == 0 {
		return nil, fmt.Errorf("country code could not be empty")
	}

	not := false
	if country[0] == '!' {
		not = true
		country = country[1:]
	}
	country = strings.ToLower(country)

	matcher, err, shared := loadGeoIPMatcherSF.Do(country, func() (router.IPMatcher, error) {
		log.Infoln("Load GeoIP rule: %s", country)
		geoLoader, err := GetGeoDataLoader(LoaderName())
		if err != nil {
			return nil, err
		}
		cidrList, err := geoLoader.LoadGeoIP(country)
		if err != nil {
			return nil, err
		}
		return router.NewGeoIPMatcher(cidrList)
	})
	if err != nil {
		if !shared {
			loadGeoIPMatcherSF.Forget(country) // don't store the error result
			log.Warnln("Load GeoIP rule: %s", country)
		}
		return nil, err
	}
	if not {
		matcher = router.NewNotIpMatcherGroup(matcher)
	}
	return matcher, nil
}

func ClearGeoSiteCache() {
	geoSettingsMu.Lock()
	defer geoSettingsMu.Unlock()
	geoSiteState.Store(newGeoSiteCache(geoSiteState.Load().generation + 1))
}

func ClearGeoIPCache() {
	loadGeoIPMatcherSF.Reset()
}
