package outbound

import (
	"context"
	"fmt"

	C "github.com/metacubex/mihomo/constant"
)

type Rematch struct {
	*Base
	subRule string
	inName  string
}

type RematchOption struct {
	BasicOption
	Name    string `proxy:"name"`
	SubRule string `proxy:"sub-rule,omitempty"`
	InName  string `proxy:"in-name,omitempty"`
}

func (l *Rematch) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	l.applyMetadata(metadata)
	return NewConn(nopConn{}, l), nil
}

func (l *Rematch) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	l.applyMetadata(metadata)
	return NewPacketConn(&nopPacketConn{}, l), nil
}

func (l *Rematch) applyMetadata(metadata *C.Metadata) {
	if l.inName != "" {
		metadata.InName = l.inName
	}
	if l.subRule != "" {
		metadata.SpecialRules = l.subRule
	} else {
		metadata.SpecialRules = ""
	}
}

func NewRematch(option RematchOption) (*Rematch, error) {
	if option.SubRule == "" && option.InName == "" {
		return nil, fmt.Errorf("rematch %s requires at least one of in-name or sub-rule", option.Name)
	}
	return &Rematch{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Type:         C.Rematch,
			ProviderName: option.ProviderName,
			UDP:          true,
		}),
		subRule: option.SubRule,
		inName:  option.InName,
	}, nil
}
