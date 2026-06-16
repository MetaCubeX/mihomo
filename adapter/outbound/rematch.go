package outbound

import (
	"context"
	"fmt"

	C "github.com/metacubex/mihomo/constant"
)

type Rematch struct {
	*Base
	targetRematchName *string
	targetSubRule     *string
}

type RematchOption struct {
	BasicOption
	Name              string  `proxy:"name"`
	TargetRematchName *string `proxy:"target-rematch-name,omitempty"`
	TargetSubRule     *string `proxy:"target-sub-rule,omitempty"`
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
	if l.targetRematchName != nil {
		metadata.RematchName = *l.targetRematchName
	}
	if l.targetSubRule != nil {
		metadata.SpecialRules = *l.targetSubRule
	}
}

func NewRematch(option RematchOption) (*Rematch, error) {
	if option.TargetRematchName == nil && option.TargetSubRule == nil {
		return nil, fmt.Errorf("rematch %s requires at least one of target-rematch-name or target-sub-rule", option.Name)
	}
	return &Rematch{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Type:         C.Rematch,
			ProviderName: option.ProviderName,
			UDP:          true,
		}),
		targetRematchName: option.TargetRematchName,
		targetSubRule:     option.TargetSubRule,
	}, nil
}
