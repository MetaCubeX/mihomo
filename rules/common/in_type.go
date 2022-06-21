package common

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	"strings"
)

type InType struct {
	*Base
	types   []C.Type
	adapter string
	payload string
}

func (u *InType) Match(metadata *C.Metadata) bool {
	for _, tp := range u.types {
		if metadata.Type == tp {
			return true
		}
	}
	return false
}

func (u *InType) RuleType() C.RuleType {
	return C.INTYPE
}

func (u *InType) Adapter() string {
	return u.adapter
}

func (u *InType) Payload() string {
	return u.payload
}

func NewInType(iTypes, adapter string) (*InType, error) {
	types := strings.Split(iTypes, "/")
	if len(types) == 0 {
		return nil, fmt.Errorf("in type could be empty")
	}

	tps, err := parseInTypes(types)
	if err != nil {
		return nil, err
	}

	return &InType{
		Base:    &Base{},
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
