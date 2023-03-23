package geodata

import (
	"fmt"
	"golang.org/x/sync/singleflight"
	"strings"

	"github.com/Dreamacro/clash/component/geodata/router"
	C "github.com/Dreamacro/clash/constant"
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

	v, err, _ := loadGeoSiteMatcherSF.Do(countryCode, func() (interface{}, error) {
		geoLoader, err := GetGeoDataLoader(geoLoaderName)
		if err != nil {
			return nil, err
		}
		return geoLoader.LoadGeoSite(countryCode)
	})
	if err != nil {
		return nil, 0, err
	}
	domains := v.([]*router.Domain)

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

	v, err, _ := loadGeoIPMatcherSF.Do(country, func() (interface{}, error) {
		geoLoader, err := GetGeoDataLoader(geoLoaderName)
		if err != nil {
			return nil, err
		}
		return geoLoader.LoadGeoIP(country)
	})
	if err != nil {
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
