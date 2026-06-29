package common

import (
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type ASN struct {
	Base
	asns        []string
	payload     string
	adapter     string
	noResolveIP bool
	isSourceIP  bool
}

func (a *ASN) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if !a.noResolveIP && !a.isSourceIP && helper.ResolveIP != nil {
		helper.ResolveIP()
	}

	ip := metadata.DstIP
	if a.isSourceIP {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}

	asn, aso := mmdb.ASNInstance().LookupASN(ip.AsSlice())
	if a.isSourceIP {
		metadata.SrcIPASN = asn + " " + aso
	} else {
		metadata.DstIPASN = asn + " " + aso
	}

	for _, ruleASN := range a.asns {
		if ruleASN == asn {
			return true, a.adapter
		}
	}

	return false, a.adapter
}

func (a *ASN) RuleType() C.RuleType {
	if a.isSourceIP {
		return C.SrcIPASN
	}
	return C.IPASN
}

func (a *ASN) Adapter() string {
	return a.adapter
}

func (a *ASN) Payload() string {
	return a.payload
}

func (a *ASN) GetASN() string {
	if len(a.asns) == 0 {
		return ""
	}
	return a.asns[0]
}

func (a *ASN) GetASNs() []string {
	return append([]string(nil), a.asns...)
}

func NewIPASN(asn string, adapter string, isSrc, noResolveIP bool) (*ASN, error) {
	asns, err := parseSlashSeparatedPayload(asn, "asn", nil)
	if err != nil {
		return nil, err
	}

	if err := geodata.InitASN(); err != nil {
		log.Errorln("can't initial ASN: %s", err)
		return nil, err
	}

	return &ASN{
		Base:        Base{},
		asns:        asns,
		payload:     strings.Join(asns, "/"),
		adapter:     adapter,
		noResolveIP: noResolveIP,
		isSourceIP:  isSrc,
	}, nil
}

var _ C.Rule = (*ASN)(nil)
