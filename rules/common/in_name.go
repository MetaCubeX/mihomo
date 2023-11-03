package common

import (
	"fmt"
	C "github.com/metacubex/mihomo/constant"
	"strings"
)

type InName struct {
	*Base
	names   []string
	adapter string
	payload string
}

func (u *InName) Match(metadata *C.Metadata) (bool, string) {
	for _, name := range u.names {
		if metadata.InName == name {
			return true, u.adapter
		}
	}
	return false, ""
}

func (u *InName) RuleType() C.RuleType {
	return C.InName
}

func (u *InName) Adapter() string {
	return u.adapter
}

func (u *InName) Payload() string {
	return u.payload
}

func NewInName(iNames, adapter string) (*InName, error) {
	names := strings.Split(iNames, "/")
	if len(names) == 0 {
		return nil, fmt.Errorf("in name couldn't be empty")
	}

	return &InName{
		Base:    &Base{},
		names:   names,
		adapter: adapter,
		payload: iNames,
	}, nil
}
