package common

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

type InType struct {
	Base
	types   []C.Type
	adapter string
	payload string
}

func (u *InType) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	for _, tp := range u.types {
		if metadata.Type == tp {
			return true, u.adapter
		}
	}
	return false, ""
}

func (u *InType) RuleType() C.RuleType {
	return C.InType
}

func (u *InType) Adapter() string {
	return u.adapter
}

func (u *InType) Payload() string {
	return u.payload
}

func NewInType(iTypes, adapter string) (*InType, error) {
	types := strings.Split(iTypes, "/")
	for i, tp := range types {
		tp = strings.TrimSpace(tp)
		if len(tp) == 0 {
			return nil, fmt.Errorf("in type couldn't be empty")
		}
		types[i] = tp
	}

	tps, err := parseInTypes(types)
	if err != nil {
		return nil, err
	}

	return &InType{
		Base:    Base{},
		types:   tps,
		adapter: adapter,
		payload: strings.ToUpper(iTypes),
	}, nil
}

func parseInTypes(tps []string) (res []C.Type, err error) {
	for _, tp := range tps {
		utp := strings.ToUpper(tp)
		var r *C.Type
		if utp == "SOCKS" {
			r, _ = C.ParseType("SOCKS4")
			res = append(res, *r)
			r, _ = C.ParseType("SOCKS5")
			res = append(res, *r)
		} else {
			r, err = C.ParseType(utp)
			if err != nil {
				return
			}
			res = append(res, *r)
		}
	}
	return
}

var _ C.Rule = (*InType)(nil)
