package dns

import (
	"net"

	"github.com/Dreamacro/clash/component/trie"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/rule/geodata"
	"github.com/Dreamacro/clash/rule/geodata/router"
	_ "github.com/Dreamacro/clash/rule/geodata/standard"
)

var multiGeoIPMatcher *router.MultiGeoIPMatcher

type fallbackIPFilter interface {
	Match(net.IP) bool
}

type geoipFilter struct {
	code string
}

func (gf *geoipFilter) Match(ip net.IP) bool {
	if multiGeoIPMatcher == nil {
		countryCode := gf.code
		countryCodePrivate := "private"
		geoLoader, err := geodata.GetGeoDataLoader("standard")
		if err != nil {
			log.Errorln("[GeoIPFilter] GetGeoDataLoader error: %s", err.Error())
			return false
		}

		recordsCN, err := geoLoader.LoadGeoIP(countryCode)
		if err != nil {
			log.Errorln("[GeoIPFilter] LoadGeoIP error: %s", err.Error())
			return false
		}

		recordsPrivate, err := geoLoader.LoadGeoIP(countryCodePrivate)
		if err != nil {
			log.Errorln("[GeoIPFilter] LoadGeoIP error: %s", err.Error())
			return false
		}

		geoips := []*router.GeoIP{
			{
				CountryCode:  countryCode,
				Cidr:         recordsCN,
				ReverseMatch: false,
			},
			{
				CountryCode:  countryCodePrivate,
				Cidr:         recordsPrivate,
				ReverseMatch: false,
			},
		}

		multiGeoIPMatcher, err = router.NewMultiGeoIPMatcher(geoips)

		if err != nil {
			log.Errorln("[GeoIPFilter] NewMultiGeoIPMatcher error: %s", err.Error())
			return false
		}
	}

	return !multiGeoIPMatcher.ApplyIp(ip)
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
