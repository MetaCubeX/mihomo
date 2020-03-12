package dns

import (
	"net"

	"github.com/Dreamacro/clash/component/mmdb"
)

type fallbackFilter interface {
	Match(net.IP) bool
}

type geoipFilter struct{}

func (gf *geoipFilter) Match(ip net.IP) bool {
	record, _ := mmdb.Instance().Country(ip)
	return record.Country.IsoCode != "CN" && record.Country.IsoCode != ""
}

type ipnetFilter struct {
	ipnet *net.IPNet
}

func (inf *ipnetFilter) Match(ip net.IP) bool {
	return inf.ipnet.Contains(ip)
}
