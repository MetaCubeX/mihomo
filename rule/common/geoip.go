package common

import (
	"fmt"
	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/config"
	"strings"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type GEOIP struct {
	country      string
	adapter      string
	noResolveIP  bool
	ruleExtra    *C.RuleExtra
	geoIPMatcher *router.GeoIPMatcher
}

func (g *GEOIP) ShouldFindProcess() bool {
	return false
}

func (g *GEOIP) RuleType() C.RuleType {
	return C.GEOIP
}

func (g *GEOIP) Match(metadata *C.Metadata) bool {
	ip := metadata.DstIP
	if ip == nil {
		return false
	}

	if strings.EqualFold(g.country, "LAN") || C.TunBroadcastAddr.Equal(ip) {
		return ip.IsPrivate()
	}
	if !config.GeodataMode {
		record, _ := mmdb.Instance().Country(ip)
		return strings.EqualFold(record.Country.IsoCode, g.country)
	}
	return g.geoIPMatcher.Match(ip)
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

func (g *GEOIP) RuleExtra() *C.RuleExtra {
	return g.ruleExtra
}

func (g *GEOIP) GetCountry() string {
	return g.country
}

func (g *GEOIP) GetIPMatcher() *router.GeoIPMatcher {
	return g.geoIPMatcher
}

func NewGEOIP(country string, adapter string, noResolveIP bool, ruleExtra *C.RuleExtra) (*GEOIP, error) {
	geoIPMatcher, recordsCount, err := geodata.LoadGeoIPMatcher(country)
	if err != nil {
		return nil, fmt.Errorf("[GeoIP] %s", err.Error())
	}

	log.Infoln("Start initial GeoIP rule %s => %s, records: %d", country, adapter, recordsCount)

	geoip := &GEOIP{
		country:      country,
		adapter:      adapter,
		noResolveIP:  noResolveIP,
		ruleExtra:    ruleExtra,
		geoIPMatcher: geoIPMatcher,
	}

	return geoip, nil
}
