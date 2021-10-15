package rules

import (
	"strings"

	"github.com/Dreamacro/clash/component/mmdb"
	C "github.com/Dreamacro/clash/constant"
	//"github.com/Dreamacro/clash/rule/geodata"
	//"github.com/Dreamacro/clash/rule/geodata/router"
	//_ "github.com/Dreamacro/clash/rule/geodata/standard"
)

type GEOIP struct {
	country     string
	adapter     string
	noResolveIP bool
	ruleExtra   *C.RuleExtra
	//geoIPMatcher *router.GeoIPMatcher
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
	record, _ := mmdb.Instance().Country(ip)
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

func (g *GEOIP) RuleExtra() *C.RuleExtra {
	return g.ruleExtra
}

func (g *GEOIP) GetCountry() string {
	return g.country
}

func NewGEOIP(country string, adapter string, noResolveIP bool, ruleExtra *C.RuleExtra) (*GEOIP, error) {
	//geoLoaderName := "standard"
	////geoLoaderName := "memconservative"
	//geoLoader, err := geodata.GetGeoDataLoader(geoLoaderName)
	//if err != nil {
	//	return nil, fmt.Errorf("load GeoIP data error, %s", err.Error())
	//}
	//
	//records, err := geoLoader.LoadGeoIP(strings.ReplaceAll(country, "!", ""))
	//if err != nil {
	//	return nil, fmt.Errorf("load GeoIP data error, %s", err.Error())
	//}
	//
	//geoIP := &router.GeoIP{
	//	CountryCode:  country,
	//	Cidr:         records,
	//	ReverseMatch: strings.Contains(country, "!"),
	//}
	//
	//geoIPMatcher, err := router.NewGeoIPMatcher(geoIP)
	//
	//if err != nil {
	//	return nil, fmt.Errorf("load GeoIP data error, %s", err.Error())
	//}
	//
	//log.Infoln("Start initial GeoIP rule %s => %s, records: %d, reverse match: %v", country, adapter, len(records), geoIP.ReverseMatch)

	geoip := &GEOIP{
		country:     country,
		adapter:     adapter,
		noResolveIP: noResolveIP,
		ruleExtra:   ruleExtra,
		//geoIPMatcher: geoIPMatcher,
	}

	return geoip, nil
}
