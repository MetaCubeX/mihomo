package geodata

import (
	"errors"
	"fmt"
	"golang.org/x/sync/singleflight"
	"strings"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var geoLoaderName = "memconservative"

//  geoLoaderName = "standard"

func LoaderName() string {
	return geoLoaderName
}

func SetLoader(newLoader string) {
	if newLoader == "memc" {
		newLoader = "memconservative"
	}
	geoLoaderName = newLoader
}

func Verify(name string) error {
	switch name {
	case C.GeositeName:
		_, _, err := LoadGeoSiteMatcher("CN")
		return err
	case C.GeoipName:
		_, _, err := LoadGeoIPMatcher("CN")
		return err
	default:
		return fmt.Errorf("not support name")
	}
}

var loadGeoSiteMatcherSF = singleflight.Group{}

func LoadGeoSiteMatcher(countryCode string) (*router.DomainMatcher, int, error) {
	if len(countryCode) == 0 {
		return nil, 0, fmt.Errorf("country code could not be empty")
	}

	not := false
	if countryCode[0] == '!' {
		not = true
		countryCode = countryCode[1:]
	}
	countryCode = strings.ToLower(countryCode)

	parts := strings.Split(countryCode, "@")
	if len(parts) == 0 {
		return nil, 0, errors.New("empty rule")
	}
	listName := strings.TrimSpace(parts[0])
	attrVal := parts[1:]

	if len(listName) == 0 {
		return nil, 0, fmt.Errorf("empty listname in rule: %s", countryCode)
	}

	v, err, shared := loadGeoSiteMatcherSF.Do(listName, func() (interface{}, error) {
		geoLoader, err := GetGeoDataLoader(geoLoaderName)
		if err != nil {
			return nil, err
		}
		return geoLoader.LoadGeoSite(listName)
	})
	if err != nil {
		if !shared {
			loadGeoSiteMatcherSF.Forget(listName) // don't store the error result
		}
		return nil, 0, err
	}
	domains := v.([]*router.Domain)

	attrs := parseAttrs(attrVal)
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
	matcher, err := router.NewMphMatcherGroup(domains, not)
	if err != nil {
		return nil, 0, err
	}

	return matcher, len(domains), nil
}

var loadGeoIPMatcherSF = singleflight.Group{}

func LoadGeoIPMatcher(country string) (*router.GeoIPMatcher, int, error) {
	if len(country) == 0 {
		return nil, 0, fmt.Errorf("country code could not be empty")
	}

	not := false
	if country[0] == '!' {
		not = true
		country = country[1:]
	}
	country = strings.ToLower(country)

	v, err, shared := loadGeoIPMatcherSF.Do(country, func() (interface{}, error) {
		geoLoader, err := GetGeoDataLoader(geoLoaderName)
		if err != nil {
			return nil, err
		}
		return geoLoader.LoadGeoIP(country)
	})
	if err != nil {
		if !shared {
			loadGeoIPMatcherSF.Forget(country) // don't store the error result
		}
		return nil, 0, err
	}
	records := v.([]*router.CIDR)

	geoIP := &router.GeoIP{
		CountryCode:  country,
		Cidr:         records,
		ReverseMatch: not,
	}

	matcher, err := router.NewGeoIPMatcher(geoIP)
	if err != nil {
		return nil, 0, err
	}
	return matcher, len(records), nil
}

func ClearCache() {
	loadGeoSiteMatcherSF = singleflight.Group{}
	loadGeoIPMatcherSF = singleflight.Group{}
}
