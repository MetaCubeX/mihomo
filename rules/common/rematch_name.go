package common

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

type RematchName struct {
	Base
	names   []string
	adapter string
	payload string
}

func (u *RematchName) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	for _, name := range u.names {
		if metadata.RematchName == name {
			return true, u.adapter
		}
	}
	return false, ""
}

func (u *RematchName) RuleType() C.RuleType {
	return C.RematchName
}

func (u *RematchName) Adapter() string {
	return u.adapter
}

func (u *RematchName) Payload() string {
	return u.payload
}

func NewRematchName(iNames, adapter string) (*RematchName, error) {
	names := strings.Split(iNames, "/")
	for i, name := range names {
		name = strings.TrimSpace(name)
		if len(name) == 0 {
			return nil, fmt.Errorf("rematch name couldn't be empty")
		}
		names[i] = name
	}

	return &RematchName{
		Base:    Base{},
		names:   names,
		adapter: adapter,
		payload: iNames,
	}, nil
}

var _ C.Rule = (*RematchName)(nil)
