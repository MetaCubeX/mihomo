package rules

import (
	"strings"

	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
)

type GEOIP struct {
	*Base
	country     string
	adapter     string
	noResolveIP bool
}

func (g *GEOIP) RuleType() C.RuleType {
	return C.GEOIP
}

func (g *GEOIP) Match(metadata *C.Metadata) bool {
	ip := metadata.DstIP
	if !ip.IsValid() {
		return false
	}

	if strings.EqualFold(g.country, "LAN") {
		return ip.IsPrivate() ||
			ip.IsUnspecified() ||
			ip.IsLoopback() ||
			ip.IsMulticast() ||
			ip.IsLinkLocalUnicast() ||
			resolver.IsFakeBroadcastIP(ip)
	}

	record, _ := mmdb.Instance().Country(ip.AsSlice())
	return strings.EqualFold(record.Country.IsoCode, g.country)
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

func NewGEOIP(country string, adapter string, noResolveIP bool) *GEOIP {
	geoip := &GEOIP{
		Base:        &Base{},
		country:     country,
		adapter:     adapter,
		noResolveIP: noResolveIP,
	}

	return geoip
}

var _ C.Rule = (*GEOIP)(nil)
