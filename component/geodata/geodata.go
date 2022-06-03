package geodata

import (
	"errors"
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	"strings"

	"github.com/Dreamacro/clash/component/geodata/router"
	"github.com/Dreamacro/clash/log"
)

type loader struct {
	LoaderImplementation
}

func (l *loader) LoadGeoSite(list string) ([]*router.Domain, error) {
	return l.LoadGeoSiteWithAttr(C.GeositeName, list)
}

func (l *loader) LoadGeoSiteWithAttr(file string, siteWithAttr string) ([]*router.Domain, error) {
	parts := strings.Split(siteWithAttr, "@")
	if len(parts) == 0 {
		return nil, errors.New("empty rule")
	}
	list := strings.TrimSpace(parts[0])
	attrVal := parts[1:]

	if len(list) == 0 {
		return nil, fmt.Errorf("empty listname in rule: %s", siteWithAttr)
	}

	domains, err := l.LoadSiteByPath(file, list)
	if err != nil {
		return nil, err
	}

	attrs := parseAttrs(attrVal)
	if attrs.IsEmpty() {
		if strings.Contains(siteWithAttr, "@") {
			log.Warnln("empty attribute list: %s", siteWithAttr)
		}
		return domains, nil
	}

	filteredDomains := make([]*router.Domain, 0, len(domains))
	hasAttrMatched := false
	for _, domain := range domains {
		if attrs.Match(domain) {
			hasAttrMatched = true
			filteredDomains = append(filteredDomains, domain)
		}
	}
	if !hasAttrMatched {
		log.Warnln("attribute match no rule: geosite: %s", siteWithAttr)
	}

	return filteredDomains, nil
}

func (l *loader) LoadGeoIP(country string) ([]*router.CIDR, error) {
	return l.LoadIPByPath(C.GeoipName, country)
}

var loaders map[string]func() LoaderImplementation

func RegisterGeoDataLoaderImplementationCreator(name string, loader func() LoaderImplementation) {
	if loaders == nil {
		loaders = map[string]func() LoaderImplementation{}
	}
	loaders[name] = loader
}

func getGeoDataLoaderImplementation(name string) (LoaderImplementation, error) {
	if geoLoader, ok := loaders[name]; ok {
		return geoLoader(), nil
	}
	return nil, fmt.Errorf("unable to locate GeoData loader %s", name)
}

func GetGeoDataLoader(name string) (Loader, error) {
	loadImpl, err := getGeoDataLoaderImplementation(name)
	if err == nil {
		return &loader{loadImpl}, nil
	}
	return nil, err
}
