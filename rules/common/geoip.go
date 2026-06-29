package common

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"golang.org/x/exp/slices"
)

type GEOIP struct {
	Base
	countries   []string
	payload     string
	adapter     string
	noResolveIP bool
	isSourceIP  bool
}

type namedGeoIPMatcher struct {
	country string
	matcher router.IPMatcher
}

type multiGeoIPMatcher []router.IPMatcher

type lanIPMatcher struct{}

func (m multiGeoIPMatcher) Match(ip netip.Addr) bool {
	for _, matcher := range m {
		if matcher.Match(ip) {
			return true
		}
	}
	return false
}

func (m multiGeoIPMatcher) Count() int {
	count := 0
	for _, matcher := range m {
		count += matcher.Count()
	}
	return count
}

func (lanIPMatcher) Match(ip netip.Addr) bool {
	return isLanIP(ip)
}

func (lanIPMatcher) Count() int {
	return 0
}

var _ C.Rule = (*GEOIP)(nil)

func (g *GEOIP) RuleType() C.RuleType {
	if g.isSourceIP {
		return C.SrcGEOIP
	}
	return C.GEOIP
}

func (g *GEOIP) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if !g.noResolveIP && !g.isSourceIP && helper.ResolveIP != nil {
		helper.ResolveIP()
	}

	ip := metadata.DstIP
	if g.isSourceIP {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}

	if g.matchLan(ip) {
		return true, g.adapter
	}
	if !g.hasNonLanCountry() {
		return false, g.adapter
	}

	if geodata.GeodataMode() {
		if g.isSourceIP {
			if g.matchCountries(metadata.SrcGeoIP) {
				return true, g.adapter
			}
		} else {
			if g.matchCountries(metadata.DstGeoIP) {
				return true, g.adapter
			}
		}

		matchers, err := g.getNamedIPMatchers()
		if err != nil {
			return false, g.adapter
		}
		for _, matcher := range matchers {
			if matcher.matcher.Match(ip) {
				if g.isSourceIP {
					metadata.SrcGeoIP = append(metadata.SrcGeoIP, matcher.country)
				} else {
					metadata.DstGeoIP = append(metadata.DstGeoIP, matcher.country)
				}
				return true, g.adapter
			}
		}

		return false, g.adapter
	}

	if g.isSourceIP {
		if metadata.SrcGeoIP != nil {
			return g.matchCountries(metadata.SrcGeoIP), g.adapter
		}
	} else {
		if metadata.DstGeoIP != nil {
			return g.matchCountries(metadata.DstGeoIP), g.adapter
		}
	}
	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	if g.isSourceIP {
		metadata.SrcGeoIP = codes
	} else {
		metadata.DstGeoIP = codes
	}
	if g.matchCountries(codes) {
		return true, g.adapter
	}
	return false, g.adapter
}

// MatchIp implements C.IpMatcher
func (g *GEOIP) MatchIp(ip netip.Addr) bool {
	match, ok := g.matchIp(ip)
	return ok && match
}

func (g *GEOIP) matchIp(ip netip.Addr) (match bool, ok bool) {
	if !ip.IsValid() {
		return false, true
	}

	if g.matchLan(ip) {
		return true, true
	}
	if !g.hasNonLanCountry() {
		return false, true
	}

	if geodata.GeodataMode() {
		matchers, err := g.getNamedIPMatchers()
		if err != nil {
			return false, false
		}
		for _, matcher := range matchers {
			if matcher.matcher.Match(ip) {
				return true, true
			}
		}
		return false, true
	}

	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	return g.matchCountries(codes), true
}

// MatchIp implements C.IpMatcher
func (g dnsFallbackFilter) MatchIp(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if g.isLan(ip) { // compatible with original behavior
		return false
	}

	match, ok := g.GEOIP.matchIp(ip)
	return ok && !match
}

type dnsFallbackFilter struct {
	*GEOIP
}

func (g *GEOIP) DnsFallbackFilter() C.IpMatcher { // for dns.fallback-filter.geoip
	return dnsFallbackFilter{GEOIP: g}
}

func (g *GEOIP) isLan(ip netip.Addr) bool {
	return isLanIP(ip)
}

func (g *GEOIP) Adapter() string {
	return g.adapter
}

func (g *GEOIP) Payload() string {
	return g.payload
}

func (g *GEOIP) GetCountry() string {
	if len(g.countries) == 0 {
		return ""
	}
	return g.countries[0]
}

func (g *GEOIP) GetCountries() []string {
	return append([]string(nil), g.countries...)
}

func (g *GEOIP) GetIPMatcher() (router.IPMatcher, error) {
	if geodata.GeodataMode() {
		return g.getCombinedIPMatcher()
	}
	if g.hasLanCountry() && !g.hasNonLanCountry() {
		return lanIPMatcher{}, nil
	}
	return nil, errors.New("not geodata mode")
}

func (g *GEOIP) getNamedIPMatchers() ([]namedGeoIPMatcher, error) {
	return g.loadNamedIPMatchers()
}

func (g *GEOIP) loadNamedIPMatchers() ([]namedGeoIPMatcher, error) {
	matchers := make([]namedGeoIPMatcher, 0, len(g.countries))
	for _, country := range g.countries {
		if country == "lan" {
			continue
		}
		matcher, err := g.getIPMatcher(country)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, namedGeoIPMatcher{country: country, matcher: matcher})
	}

	if len(matchers) == 0 {
		return nil, errors.New("geoip matcher has no data")
	}
	return matchers, nil
}

func (g *GEOIP) getCombinedIPMatcher() (router.IPMatcher, error) {
	matchers := make(multiGeoIPMatcher, 0, len(g.countries))
	if g.hasLanCountry() {
		matchers = append(matchers, lanIPMatcher{})
	}
	if g.hasNonLanCountry() {
		namedMatchers, err := g.getNamedIPMatchers()
		if err != nil {
			return nil, err
		}
		for _, matcher := range namedMatchers {
			matchers = append(matchers, matcher.matcher)
		}
	}

	return newMultiGeoIPMatcher(matchers)
}

func newMultiGeoIPMatcher(matchers []router.IPMatcher) (router.IPMatcher, error) {
	if len(matchers) == 0 {
		return nil, errors.New("geoip matcher has no data")
	}
	if len(matchers) == 1 {
		return matchers[0], nil
	}
	return multiGeoIPMatcher(matchers), nil
}

func (g *GEOIP) getIPMatcher(country string) (router.IPMatcher, error) {
	geoIPMatcher, err := geodata.LoadGeoIPMatcher(country)
	if err != nil {
		return nil, fmt.Errorf("[GeoIP] %w", err)
	}
	return geoIPMatcher, nil

}

func (g *GEOIP) GetRecodeSize() int {
	if !g.hasNonLanCountry() {
		return 0
	}

	if matcher, err := g.GetIPMatcher(); err == nil {
		return matcher.Count()
	}
	return 0
}

func NewGEOIP(country string, adapter string, isSrc, noResolveIP bool) (*GEOIP, error) {
	countries, err := parseSlashSeparatedPayload(country, "geoip country", strings.ToLower)
	if err != nil {
		return nil, err
	}

	geoip := &GEOIP{
		Base:        Base{},
		countries:   countries,
		payload:     strings.Join(countries, "/"),
		adapter:     adapter,
		noResolveIP: noResolveIP,
		isSourceIP:  isSrc,
	}

	allLan := true
	for _, country := range countries {
		if country != "lan" {
			allLan = false
			break
		}
	}

	if allLan {
		return geoip, nil
	}

	if err := geodata.InitGeoIP(); err != nil {
		log.Errorln("can't initial GeoIP: %s", err)
		return nil, err
	}

	if geodata.GeodataMode() {
		matcher, err := geoip.getCombinedIPMatcher() // test load
		if err != nil {
			return nil, err
		}
		log.Infoln("Finished initial GeoIP rule %s => %s, records: %d", geoip.payload, adapter, matcher.Count())
	}

	return geoip, nil
}

func (g *GEOIP) matchLan(ip netip.Addr) bool {
	for _, country := range g.countries {
		if country == "lan" {
			return isLanIP(ip)
		}
	}
	return false
}

func (g *GEOIP) matchCountries(codes []string) bool {
	for _, country := range g.countries {
		if country == "lan" {
			continue
		}
		if slices.Contains(codes, country) {
			return true
		}
	}
	return false
}

func (g *GEOIP) hasNonLanCountry() bool {
	for _, country := range g.countries {
		if country != "lan" {
			return true
		}
	}
	return false
}

func (g *GEOIP) hasLanCountry() bool {
	for _, country := range g.countries {
		if country == "lan" {
			return true
		}
	}
	return false
}

func isLanIP(ip netip.Addr) bool {
	return ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast()
}

var _ C.Rule = (*GEOIP)(nil)
