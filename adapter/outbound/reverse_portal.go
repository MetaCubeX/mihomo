package outbound

import (
	"context"
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/reverse"
	"github.com/metacubex/mihomo/transport/muxcool"
)

// ReversePortal —— 反向代理 Portal 侧的"出站"。用户流量按 routing 命中它后,
// DialContext 经 reverse 表(同 `tag`)挑一条活跃 Bridge 隧道开 Mux.cool 子流下发。
// 与 listener/inbound 的 reverse-portal 由相同 `tag` 关联。
type ReversePortal struct {
	*Base
	tag string
}

type ReversePortalOption struct {
	BasicOption
	Name string `proxy:"name"`
	Tag  string `proxy:"tag"`
}

func NewReversePortal(option ReversePortalOption) (*ReversePortal, error) {
	return &ReversePortal{
		Base: NewBase(BaseOption{
			Name: option.Name,
			Addr: "reverse-portal:" + option.Tag,
			Type: C.Compatible,
			UDP:  true,
		}),
		tag: option.Tag,
	}, nil
}

// SupportUDP —— 反向 Portal 支持 UDP(经 Mux.cool UDP 子流下发 Bridge 落地)。
func (r *ReversePortal) SupportUDP() bool { return true }

func metaToAddr(metadata *C.Metadata) muxcool.Address {
	if metadata.Host != "" {
		return muxcool.Address{IsDomain: true, Domain: metadata.Host}
	}
	return muxcool.Address{IP: net.IP(metadata.DstIP.AsSlice())}
}

// DialContext implements C.ProxyAdapter
func (r *ReversePortal) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := reverse.Open(r.tag, muxcool.NetworkTCP, metaToAddr(metadata), metadata.DstPort)
	if err != nil {
		return nil, err
	}
	return NewConn(c, r), nil
}

// ListenPacketContext implements C.ProxyAdapter —— UDP:返回全锥 PacketConn,按 target 开 Mux.cool UDP 子流。
func (r *ReversePortal) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := reverse.NewPacketConn(r.tag)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, r), nil
}

var _ C.ProxyAdapter = (*ReversePortal)(nil)
