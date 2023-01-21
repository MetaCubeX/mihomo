package dns

import (
	"net/netip"

	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"strings"
)

type fallbackIPFilter interface {
	Match(netip.Addr) bool
}

type geoipFilter struct {
	code string
}

var geoIPMatcher *router.GeoIPMatcher

func (gf *geoipFilter) Match(ip netip.Addr) bool {
	if !C.GeodataMode {
		record, _ := mmdb.Instance().Country(ip.AsSlice())
		return !strings.EqualFold(record.Country.IsoCode, gf.code) && !ip.IsPrivate()
	}

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
	return !geoIPMatcher.Match(ip.AsSlice())
}

type ipnetFilter struct {
	ipnet *netip.Prefix
}

func (inf *ipnetFilter) Match(ip netip.Addr) bool {
	return inf.ipnet.Contains(ip)
}

type fallbackDomainFilter interface {
	Match(domain string) bool
}

type domainFilter struct {
	tree *trie.DomainTrie[struct{}]
}

func NewDomainFilter(domains []string) *domainFilter {
	df := domainFilter{tree: trie.New[struct{}]()}
	for _, domain := range domains {
		_ = df.tree.Insert(domain, struct{}{})
	}
	df.tree.Optimize()
	return &df
}

func (df *domainFilter) Match(domain string) bool {
	return df.tree.Search(domain) != nil
}

type geoSiteFilter struct {
	matchers []*router.DomainMatcher
}

func NewGeoSite(group string) (fallbackDomainFilter, error) {
	matcher, _, err := geodata.LoadGeoSiteMatcher(group)
	if err != nil {
		return nil, err
	}
	filter := &geoSiteFilter{
		matchers: []*router.DomainMatcher{matcher},
	}
	return filter, nil
}

func (gsf *geoSiteFilter) Match(domain string) bool {
	for _, matcher := range gsf.matchers {
		if matcher.ApplyDomain(domain) {
			return true
		}
	}
	return false
}
