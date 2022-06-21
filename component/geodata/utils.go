package geodata

import (
	"fmt"
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

func LoadGeoSiteMatcher(countryCode string) (*router.DomainMatcher, int, error) {
	if len(countryCode) == 0 {
		return nil, 0, fmt.Errorf("country code could not be empty")
	}

	not := false
	if countryCode[0] == '!' {
		not = true
		countryCode = countryCode[1:]
	}

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
	matcher, err := router.NewMphMatcherGroup(domains, not)
	if err != nil {
		return nil, 0, err
	}

	return matcher, len(domains), nil
}

func LoadGeoIPMatcher(country string) (*router.GeoIPMatcher, int, error) {
	if len(country) == 0 {
		return nil, 0, fmt.Errorf("country code could not be empty")
	}
	geoLoader, err := GetGeoDataLoader(geoLoaderName)
	if err != nil {
		return nil, 0, err
	}

	not := false
	if country[0] == '!' {
		not = true
		country = country[1:]
	}

	records, err := geoLoader.LoadGeoIP(country)
	if err != nil {
		return nil, 0, err
	}

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
