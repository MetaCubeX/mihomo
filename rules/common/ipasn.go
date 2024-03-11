package common

import (
	"strconv"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type ASN struct {
	*Base
	asn         string
	adapter     string
	noResolveIP bool
}

func (a *ASN) Match(metadata *C.Metadata) (bool, string) {
	ip := metadata.DstIP
	if !ip.IsValid() {
		return false, ""
	}

	result := mmdb.ASNInstance().LookupASN(ip.AsSlice())

	asnNumber := strconv.FormatUint(uint64(result.AutonomousSystemNumber), 10)
	metadata.DstIPASN = asnNumber + " " + result.AutonomousSystemOrganization

	match := a.asn == asnNumber
	return match, a.adapter
}

func (a *ASN) RuleType() C.RuleType {
	return C.IPASN
}

func (a *ASN) Adapter() string {
	return a.adapter
}

func (a *ASN) Payload() string {
	return a.asn
}

func (a *ASN) ShouldResolveIP() bool {
	return !a.noResolveIP
}

func (a *ASN) GetASN() string {
	return a.asn
}

func NewIPASN(asn string, adapter string, noResolveIP bool) (*ASN, error) {
	C.ASNEnable = true
	if err := geodata.InitASN(); err != nil {
		log.Errorln("can't initial ASN: %s", err)
		return nil, err
	}

	return &ASN{
		Base:        &Base{},
		asn:         asn,
		adapter:     adapter,
		noResolveIP: noResolveIP,
	}, nil
}
