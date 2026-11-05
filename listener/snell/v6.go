package snell

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	singsnell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/mihomo/transport/singsnell/snellv6"

	"github.com/metacubex/sing/common/bufio/deadline"
	M "github.com/metacubex/sing/common/metadata"
	singN "github.com/metacubex/sing/common/network"
)

// newV6Service validates the v6 specific parts of the config and builds the
// snellv6 server bound to a handler that forwards into the mihomo tunnel.
func newV6Service(config LC.SnellServer, tunnel C.Tunnel) (*snellv6.Service, error) {
	// snell-server v6 rejects PSKs outside the 12..255-byte range
	if len(config.Psk) < 12 || len(config.Psk) > 255 {
		return nil, errors.New("snell inbound version 6 psk length must be between 12 and 255 bytes")
	}
	if config.ObfsMode != "" {
		// v6 replaced the simple-obfs layer with PSK-derived traffic shaping
		return nil, fmt.Errorf("snell inbound version 6 does not support obfs mode %s", config.ObfsMode)
	}
	mode, err := snellv6.ParseMode(config.Mode)
	if err != nil {
		return nil, fmt.Errorf("snell inbound %w", err)
	}
	handler, err := newV6Handler(tunnel, config.UDP)
	if err != nil {
		return nil, err
	}
	return snellv6.NewService(snellv6.ServerOptions{
		PSK:     []byte(config.Psk),
		Mode:    mode,
		Handler: handler,
	})
}

// handleV6Conn hands a freshly accepted (and already shadow-tls/restls/jls
// unwrapped) connection to the snellv6 server. Per-connection additions (such
// as the outer layer's user) travel through the context so a single handler can
// serve every connection. Ownership of rawConn moves to the service/handler on
// success; it is only closed here when the handshake fails.
func (l *Listener) handleV6Conn(rawConn net.Conn, additions ...inbound.Addition) {
	ctx := sing.WithAdditions(context.Background(), additions...)
	ctx = sing.WithInAddr(ctx, rawConn.LocalAddr())
	source := M.SocksaddrFromNet(rawConn.RemoteAddr())
	err := l.v6.NewConnection(ctx, rawConn, source, func(error) {})
	if err != nil {
		_ = rawConn.Close()
		log.Debugln("snell v6 inbound from %s: %v", rawConn.RemoteAddr(), err)
	}
}

// v6Handler bridges snellv6's TCPConnectionHandlerEx / UDPConnectionHandlerEx
// callbacks into mihomo tunnel calls. TCP is handled directly, UDP reuses the
// packet loop of the sing listener bridge.
type v6Handler struct {
	tunnel C.Tunnel
	udp    bool
	packet *sing.ListenerHandler
}

func newV6Handler(tunnel C.Tunnel, udp bool) (*v6Handler, error) {
	packetHandler, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:     tunnel,
		Type:       C.SNELL,
		UDPTimeout: sing.UDPTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &v6Handler{tunnel: tunnel, udp: udp, packet: packetHandler}, nil
}

func (h *v6Handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose singsnell.CloseHandlerFunc) {
	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = N.NewDeadlineConn(conn) // conn from sing should check NeedAdditionalReadDeadline
	}

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.SNELL,
	}
	if source.IsIP() && source.Fqdn == "" {
		metadata.RawSrcAddr = source.Unwrap().TCPAddr()
	}
	if destination.IsIP() && destination.Fqdn == "" {
		metadata.RawDstAddr = destination.Unwrap().TCPAddr()
	}
	inbound.ApplyAdditions(metadata, inbound.WithDstAddr(destination), inbound.WithSrcAddr(source), inbound.WithInAddr(conn.LocalAddr()))
	inbound.ApplyAdditions(metadata, sing.AdditionsFromContext(ctx)...)

	// The reuse session blocks until onClose is called, so the tunnel must run
	// in its own goroutine. HandleTCPConn closes conn once both directions end.
	go func() {
		h.tunnel.HandleTCPConn(conn, metadata)
		if onClose != nil {
			onClose(nil)
		}
	}()
}

func (h *v6Handler) NewPacketConnectionEx(ctx context.Context, conn singN.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose singsnell.CloseHandlerFunc) {
	if !h.udp {
		_ = conn.Close()
		if onClose != nil {
			onClose(errors.New("snell UDP is disabled"))
		}
		return
	}
	go func() {
		err := h.packet.NewPacketConnection(ctx, conn, M.Metadata{
			Source:      source,
			Destination: destination,
		})
		if onClose != nil {
			onClose(err)
		}
	}()
}

var _ singsnell.Handler = (*v6Handler)(nil)
