package common

import (
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// ASNOrg matches the autonomous system organization of an IP by a case-insensitive keyword
type ASNOrg struct {
	Base
	org         string
	keyword     string
	adapter     string
	noResolveIP bool
	isSourceIP  bool
}

func (a *ASNOrg) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
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

	if aso == "" {
		return false, ""
	}
	return strings.Contains(strings.ToLower(aso), a.keyword), a.adapter
}

func (a *ASNOrg) RuleType() C.RuleType {
	if a.isSourceIP {
		return C.SrcIPASNOrg
	}
	return C.IPASNOrg
}

func (a *ASNOrg) Adapter() string {
	return a.adapter
}

func (a *ASNOrg) Payload() string {
	return a.org
}

func NewIPASNOrg(org string, adapter string, isSrc, noResolveIP bool) (*ASNOrg, error) {
	if err := geodata.InitASN(); err != nil {
		log.Errorln("can't initial ASN: %s", err)
		return nil, err
	}

	return &ASNOrg{
		Base:        Base{},
		org:         org,
		keyword:     strings.ToLower(org),
		adapter:     adapter,
		noResolveIP: noResolveIP,
		isSourceIP:  isSrc,
	}, nil
}

var _ C.Rule = (*ASNOrg)(nil)
