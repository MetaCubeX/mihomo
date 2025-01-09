package common

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"golang.org/x/exp/slices"
)

type GEOIP struct {
	*Base
	country     string
	adapter     string
	noResolveIP bool
	isSourceIP  bool
}

var _ C.Rule = (*GEOIP)(nil)

func (g *GEOIP) RuleType() C.RuleType {
	if g.isSourceIP {
		return C.SrcGEOIP
	}
	return C.GEOIP
}

func (g *GEOIP) Match(metadata *C.Metadata) (bool, string) {
	ip := metadata.DstIP
	if g.isSourceIP {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}

	if g.country == "lan" {
		return g.isLan(ip), g.adapter
	}

	if geodata.GeodataMode() {
		if g.isSourceIP {
			if slices.Contains(metadata.SrcGeoIP, g.country) {
				return true, g.adapter
			}
		} else {
			if slices.Contains(metadata.DstGeoIP, g.country) {
				return true, g.adapter
			}
		}
		matcher, err := g.getIPMatcher()
		if err != nil {
			return false, ""
		}
		match := matcher.Match(ip)
		if match {
			if g.isSourceIP {
				metadata.SrcGeoIP = append(metadata.SrcGeoIP, g.country)
			} else {
				metadata.DstGeoIP = append(metadata.DstGeoIP, g.country)
			}
		}
		return match, g.adapter
	}

	if g.isSourceIP {
		if metadata.SrcGeoIP != nil {
			return slices.Contains(metadata.SrcGeoIP, g.country), g.adapter
		}
	} else {
		if metadata.DstGeoIP != nil {
			return slices.Contains(metadata.DstGeoIP, g.country), g.adapter
		}
	}
	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	if g.isSourceIP {
		metadata.SrcGeoIP = codes
	} else {
		metadata.DstGeoIP = codes
	}
	if slices.Contains(codes, g.country) {
		return true, g.adapter
	}
	return false, ""
}

// MatchIp implements C.IpMatcher
func (g *GEOIP) MatchIp(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if g.country == "lan" {
		return g.isLan(ip)
	}

	if geodata.GeodataMode() {
		matcher, err := g.getIPMatcher()
		if err != nil {
			return false
		}
		return matcher.Match(ip)
	}

	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	return slices.Contains(codes, g.country)
}

// MatchIp implements C.IpMatcher
func (g dnsFallbackFilter) MatchIp(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if g.isLan(ip) { // compatible with original behavior
		return false
	}

	if geodata.GeodataMode() {
		matcher, err := g.getIPMatcher()
		if err != nil {
			return false
		}
		return !matcher.Match(ip)
	}

	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	return !slices.Contains(codes, g.country)
}

type dnsFallbackFilter struct {
	*GEOIP
}

func (g *GEOIP) DnsFallbackFilter() C.IpMatcher { // for dns.fallback-filter.geoip
	return dnsFallbackFilter{GEOIP: g}
}

func (g *GEOIP) isLan(ip netip.Addr) bool {
	return ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		resolver.IsFakeBroadcastIP(ip)
}

func (g *GEOIP) Adapter() string {
	return g.adapter
}

func (g *GEOIP) Payload() string {
	return g.country
}

func (g *GEOIP) ShouldResolveIP() bool {
	return !g.noResolveIP
}

func (g *GEOIP) GetCountry() string {
	return g.country
}

func (g *GEOIP) GetIPMatcher() (router.IPMatcher, error) {
	if geodata.GeodataMode() {
		return g.getIPMatcher()
	}
	return nil, errors.New("not geodata mode")
}

func (g *GEOIP) getIPMatcher() (router.IPMatcher, error) {
	geoIPMatcher, err := geodata.LoadGeoIPMatcher(g.country)
	if err != nil {
		return nil, fmt.Errorf("[GeoIP] %w", err)
	}
	return geoIPMatcher, nil

}

func (g *GEOIP) GetRecodeSize() int {
	if matcher, err := g.GetIPMatcher(); err == nil {
		return matcher.Count()
	}
	return 0
}

func NewGEOIP(country string, adapter string, isSrc, noResolveIP bool) (*GEOIP, error) {
	country = strings.ToLower(country)

	geoip := &GEOIP{
		Base:        &Base{},
		country:     country,
		adapter:     adapter,
		noResolveIP: noResolveIP,
		isSourceIP:  isSrc,
	}

	if country == "lan" {
		return geoip, nil
	}

	if err := geodata.InitGeoIP(); err != nil {
		log.Errorln("can't initial GeoIP: %s", err)
		return nil, err
	}

	if geodata.GeodataMode() {
		geoIPMatcher, err := geoip.getIPMatcher() // test load
		if err != nil {
			return nil, err
		}
		log.Infoln("Finished initial GeoIP rule %s => %s, records: %d", country, adapter, geoIPMatcher.Count())
	}

	return geoip, nil
}
