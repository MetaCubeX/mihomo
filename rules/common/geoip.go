package common

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type GEOIP struct {
	*Base
	country      string
	adapter      string
	noResolveIP  bool
	geoIPMatcher *router.GeoIPMatcher
	recodeSize   int
}

func (g *GEOIP) RuleType() C.RuleType {
	return C.GEOIP
}

func (g *GEOIP) Match(metadata *C.Metadata) (bool, string) {
	ip := metadata.DstIP
	if !ip.IsValid() {
		return false, ""
	}

	if strings.EqualFold(g.country, "LAN") {
		return ip.IsPrivate() ||
			ip.IsUnspecified() ||
			ip.IsLoopback() ||
			ip.IsMulticast() ||
			ip.IsLinkLocalUnicast() ||
			resolver.IsFakeBroadcastIP(ip), g.adapter
	}
	if !C.GeodataMode {
		codes := mmdb.Instance().LookupCode(ip.AsSlice())
		for _, code := range codes {
			if strings.EqualFold(code, g.country) {
				return true, g.adapter
			}
		}
		return false, g.adapter
	}
	return g.geoIPMatcher.Match(ip.AsSlice()), g.adapter
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

func (g *GEOIP) GetIPMatcher() *router.GeoIPMatcher {
	return g.geoIPMatcher
}

func (g *GEOIP) GetRecodeSize() int {
	return g.recodeSize
}

func NewGEOIP(country string, adapter string, noResolveIP bool) (*GEOIP, error) {
	if err := geodata.InitGeoIP(); err != nil {
		log.Errorln("can't initial GeoIP: %s", err)
		return nil, err
	}

	if !C.GeodataMode || strings.EqualFold(country, "LAN") {
		geoip := &GEOIP{
			Base:        &Base{},
			country:     country,
			adapter:     adapter,
			noResolveIP: noResolveIP,
		}
		return geoip, nil
	}

	geoIPMatcher, size, err := geodata.LoadGeoIPMatcher(country)
	if err != nil {
		return nil, fmt.Errorf("[GeoIP] %s", err.Error())
	}

	log.Infoln("Start initial GeoIP rule %s => %s, records: %d", country, adapter, size)
	geoip := &GEOIP{
		Base:         &Base{},
		country:      country,
		adapter:      adapter,
		noResolveIP:  noResolveIP,
		geoIPMatcher: geoIPMatcher,
		recodeSize:   size,
	}
	return geoip, nil
}

//var _ C.Rule = (*GEOIP)(nil)
