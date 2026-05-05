package outbound

import (
	"context"
	"fmt"

	C "github.com/metacubex/mihomo/constant"
)

type Loopback struct {
	*Base
	subRule string
	inName  string
}

type LoopbackOption struct {
	BasicOption
	Name    string `proxy:"name"`
	SubRule string `proxy:"sub-rule,omitempty"`
	InName  string `proxy:"in-name,omitempty"`
}

func (l *Loopback) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	l.applyMetadata(metadata)
	return NewConn(nopConn{}, l), nil
}

func (l *Loopback) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	l.applyMetadata(metadata)
	return NewPacketConn(&nopPacketConn{}, l), nil
}

func (l *Loopback) LoopbackConfig() (subRule, inName string) {
	return l.subRule, l.inName
}

func (l *Loopback) applyMetadata(metadata *C.Metadata) {
	if l.inName != "" {
		metadata.InName = l.inName
	}
	if l.subRule != "" {
		metadata.SpecialRules = l.subRule
	} else {
		metadata.SpecialRules = ""
	}
}

func NewLoopback(option LoopbackOption) (*Loopback, error) {
	if option.SubRule == "" && option.InName == "" {
		return nil, fmt.Errorf("loopback %s requires at least one of in-name or sub-rule", option.Name)
	}
	return &Loopback{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Type:         C.Loopback,
			ProviderName: option.ProviderName,
			UDP:          true,
		}),
		subRule: option.SubRule,
		inName:  option.InName,
	}, nil
}
