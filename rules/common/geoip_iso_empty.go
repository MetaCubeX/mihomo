package common

import (
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
)

type ISOEmpty struct {
	adapter string
}

func (g *ISOEmpty) RuleType() C.RuleType {
	return C.ISOEmpty
}

func (g *ISOEmpty) Match(metadata *C.Metadata) (bool, string) {
	ip := metadata.DstIP
	if !ip.IsValid() {
		return false, g.adapter
	}
	if metadata.GeoedIp() {
		return false, g.adapter
	}
	metadata.DstGeoIP = mmdb.IPInstance().LookupCode(ip.AsSlice())
	if metadata.GeoedIp() {
		return false, g.adapter
	}
	return true, g.adapter
}

func (g *ISOEmpty) Adapter() string {
	return g.adapter
}

func (g *ISOEmpty) Payload() string {
	return "ISO_Empty"
}

func (g *ISOEmpty) ShouldResolveIP() bool {
	return true
}

func (g *ISOEmpty) ShouldFindProcess() bool {
	return false
}

func NewISOEmpty(adapter string) *ISOEmpty {
	isoEmpty := &ISOEmpty{
		adapter: adapter,
	}

	return isoEmpty
}
