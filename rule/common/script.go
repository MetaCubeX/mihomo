package common

import (
	"github.com/Dreamacro/clash/component/js"
	C "github.com/Dreamacro/clash/constant"
	"github.com/gofrs/uuid"
)

type Script struct {
	*Base
	adapter string
	name    string
}

func (s *Script) RuleType() C.RuleType {
	return C.Script
}

func (s *Script) Match(metadata *C.Metadata) bool {
	res := false
	js.Run(s.name, map[string]any{
		"metadata": metadata,
	}, func(a any, err error) {
		if err != nil {
			res = false
		}

		r, ok := a.(bool)
		if !ok {
			res = false
		}

		res = r
	})

	return res
}

func (s *Script) Adapter() string {
	return s.adapter
}

func (s *Script) Payload() string {
	return s.adapter
}

func (s *Script) ShouldResolveIP() bool {
	return true
}

func NewScript(script string, adapter string) (*Script, error) {
	name, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	if err := js.NewJS(name.String(), script); err != nil {
		return nil, err
	}

	return &Script{
		Base:    &Base{},
		adapter: adapter,
		name:    name.String(),
	}, nil
}

var _ C.Rule = (*Script)(nil)
