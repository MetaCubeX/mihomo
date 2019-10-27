package rules

import (
	"sync"

	C "github.com/Dreamacro/clash/constant"

	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
)

var (
	mmdb *geoip2.Reader
	once sync.Once
)

type GEOIP struct {
	country string
	adapter string
}

func (g *GEOIP) RuleType() C.RuleType {
	return C.GEOIP
}

func (g *GEOIP) IsMatch(metadata *C.Metadata) bool {
	if metadata.DstIP == nil {
		return false
	}
	record, _ := mmdb.Country(metadata.DstIP)
	return record.Country.IsoCode == g.country
}

func (g *GEOIP) Adapter() string {
	return g.adapter
}

func (g *GEOIP) Payload() string {
	return g.country
}

func NewGEOIP(country string, adapter string) *GEOIP {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.Open(C.Path.MMDB())
		if err != nil {
			log.Fatalf("Can't load mmdb: %s", err.Error())
		}
	})
	return &GEOIP{
		country: country,
		adapter: adapter,
	}
}
