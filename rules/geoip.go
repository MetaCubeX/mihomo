package rules

import (
	"net"

	C "github.com/Dreamacro/clash/constant"

	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
)

var mmdb *geoip2.Reader

func init() {
	var err error
	mmdb, err = geoip2.Open(C.MMDBPath)
	if err != nil {
		log.Fatalf("Can't load mmdb: %s", err.Error())
	}
}

type GEOIP struct {
	country string
	adapter string
}

func (g *GEOIP) RuleType() C.RuleType {
	return C.GEOIP
}

func (g *GEOIP) IsMatch(addr *C.Addr) bool {
	if addr.AddrType == C.AtypDomainName {
		return false
	}
	dstIP := net.ParseIP(addr.Host)
	if dstIP == nil {
		return false
	}
	record, _ := mmdb.Country(dstIP)
	return record.Country.IsoCode == g.country
}

func (g *GEOIP) Adapter() string {
	return g.adapter
}

func NewGEOIP(country string, adapter string) *GEOIP {
	return &GEOIP{
		country: country,
		adapter: adapter,
	}
}
