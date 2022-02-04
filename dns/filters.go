package dns

import (
	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	"github.com/Dreamacro/clash/component/trie"
	"github.com/Dreamacro/clash/log"
	"net"
)

type fallbackIPFilter interface {
	Match(net.IP) bool
}

type geoipFilter struct {
	code string
}

var geoIPMatcher *router.GeoIPMatcher

func (gf *geoipFilter) Match(ip net.IP) bool {
	if geoIPMatcher == nil {
		countryCode := "cn"
		geoLoader, err := geodata.GetGeoDataLoader(geodata.LoaderName())
		if err != nil {
			log.Errorln("[GeoIPFilter] GetGeoDataLoader error: %s", err.Error())
			return false
		}

		records, err := geoLoader.LoadGeoIP(countryCode)
		if err != nil {
			log.Errorln("[GeoIPFilter] LoadGeoIP error: %s", err.Error())
			return false
		}

		geoIP := &router.GeoIP{
			CountryCode:  countryCode,
			Cidr:         records,
			ReverseMatch: false,
		}

		geoIPMatcher, err = router.NewGeoIPMatcher(geoIP)

		if err != nil {
			log.Errorln("[GeoIPFilter] NewGeoIPMatcher error: %s", err.Error())
			return false
		}
	}

	return !geoIPMatcher.Match(ip)
}

type ipnetFilter struct {
	ipnet *net.IPNet
}

func (inf *ipnetFilter) Match(ip net.IP) bool {
	return inf.ipnet.Contains(ip)
}

type fallbackDomainFilter interface {
	Match(domain string) bool
}

type domainFilter struct {
	tree *trie.DomainTrie
}

func NewDomainFilter(domains []string) *domainFilter {
	df := domainFilter{tree: trie.New()}
	for _, domain := range domains {
		df.tree.Insert(domain, "")
	}
	return &df
}

func (df *domainFilter) Match(domain string) bool {
	return df.tree.Search(domain) != nil
}

type geoSiteFilter struct {
	matchers []*router.DomainMatcher
}

func (gsf *geoSiteFilter) Match(domain string) bool {
	for _, matcher := range gsf.matchers {
		if matcher.ApplyDomain(domain) {
			return true
		}
	}
	return false
}
