package outbound

import (
	"context"
	"errors"
	"github.com/Dreamacro/clash/component/dialer"

	C "github.com/Dreamacro/clash/constant"
)

type Pass struct {
	*Base
}

// DialContext implements C.ProxyAdapter
func (r *Pass) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	return nil, errors.New("match Pass rule")
}

// ListenPacketContext implements C.ProxyAdapter
func (r *Pass) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return nil, errors.New("match Pass rule")
}

func NewPass() *Pass {
	return &Pass{
		Base: &Base{
			name: "PASS",
			tp:   C.Pass,
			udp:  true,
		},
	}
}
