package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/transport/tuic/common"
	warpprotocol "github.com/metacubex/mihomo/transport/warp"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

type warpL4 struct {
	*Base
	option   WarpOption
	owner    *Warp
	client   *warpprotocol.L4Client
	resolver resolver.Resolver

	tlsConfig  *tls.Config
	quicConfig *quic.Config
	runCtx     context.Context
	runCancel  context.CancelFunc
}

func newWARPL4(owner *Warp, server string, port int, tlsConfig *tls.Config) (*warpL4, error) {
	ctx, cancel := context.WithCancel(context.Background())
	outbound := &warpL4{
		Base: NewBase(BaseOption{
			Name:         owner.option.Name,
			Addr:         net.JoinHostPort(server, fmt.Sprint(port)),
			Type:         C.Warp,
			ProviderName: owner.option.ProviderName,
			UDP:          false,
			Interface:    owner.option.Interface,
			RoutingMark:  owner.option.RoutingMark,
			Prefer:       owner.option.IPVersion,
		}),
		option:     owner.option,
		owner:      owner,
		tlsConfig:  tlsConfig.Clone(),
		quicConfig: &quic.Config{KeepAlivePeriod: 30 * time.Second},
		runCtx:     ctx,
		runCancel:  cancel,
	}
	outbound.tlsConfig.NextProtos = []string{http3.NextProtoH3}
	outbound.dialer = owner.option.NewDialer(outbound.DialOptions())
	outbound.client = warpprotocol.NewL4Client(outbound.runCtx, outbound.dialQUIC)

	if owner.option.RemoteDnsResolve && len(owner.option.Dns) > 0 {
		nss, err := dns.ParseNameServer(owner.option.Dns)
		if err != nil {
			cancel()
			return nil, err
		}
		for index := range nss {
			nss[index].ProxyAdapter = outbound
		}
		outbound.resolver = dns.NewResolver(dns.Config{Main: nss, IPv6: true})
	}
	return outbound, nil
}

func (w *warpL4) dialQUIC(ctx context.Context) (net.PacketConn, *quic.Conn, error) {
	packetConn, quicConn, err := common.DialQuic(
		ctx,
		w.addr,
		w.DialOptions(),
		w.dialer,
		w.tlsConfig,
		w.quicConfig,
		common.DialQuicOption{ConnectionIDLength: warpConnectionIDLength},
	)
	if err != nil {
		return nil, nil, err
	}
	common.SetCongestionController(quicConn, w.option.CongestionController, w.option.CWND, w.option.BBRProfile)
	return packetConn, quicConn, nil
}

func (w *warpL4) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	if !metadata.Resolved() || w.resolver != nil {
		activeResolver := resolver.DefaultResolver
		if w.resolver != nil {
			activeResolver = w.resolver
		}
		options := w.DialOptions()
		options = append(options, dialer.WithResolver(activeResolver), dialer.WithNetDialer(w.client))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = w.client.DialContext(ctx, "tcp", metadata.AddrPort().String())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("warp: L4 connection is nil")
	}
	return NewConn(conn, w.owner), nil
}

func (w *warpL4) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("warp: h3-l4proxy doesn't support UDP")
}

func (w *warpL4) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || w.resolver != nil) && metadata.Host != "" {
		activeResolver := resolver.DefaultResolver
		if w.resolver != nil {
			activeResolver = w.resolver
		}
		ip, err := resolveIPWithResolver(ctx, metadata.Host, w.prefer, activeResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (w *warpL4) ProxyInfo() C.ProxyInfo {
	info := w.Base.ProxyInfo()
	info.DialerProxy = w.option.DialerProxy
	return info
}

func (w *warpL4) IsL3Protocol(*C.Metadata) bool { return true }

func (w *warpL4) Close() error {
	w.runCancel()
	if w.client != nil {
		return w.client.Close()
	}
	return nil
}
