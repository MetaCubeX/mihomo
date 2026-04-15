package common

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/dialer"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type PacketDialer interface {
	ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error)
}

func DialQuic(ctx context.Context, address string, opts []dialer.Option, pDialer PacketDialer, tlsConf *tls.Config, conf *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
	d := dialer.NewDialer(
		dialer.WithOptions(opts...),
		dialer.WithNetDialer(dialer.NetDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			addrPort, err := netip.ParseAddrPort(address) // the dialer will resolve the domain to ip
			if err != nil {
				return nil, err
			}
			udpAddr := net.UDPAddrFromAddrPort(addrPort)
			packetConn, err := pDialer.ListenPacket(ctx, "udp", "", udpAddr.AddrPort())
			if err != nil {
				return nil, err
			}
			transport := quic.Transport{Conn: packetConn}
			transport.SetCreatedConn(true) // auto close conn
			transport.SetSingleUse(true)   // auto close transport

			var quicConn *quic.Conn
			if early {
				quicConn, err = transport.DialEarly(ctx, udpAddr, tlsConf, conf)
			} else {
				quicConn, err = transport.Dial(ctx, udpAddr, tlsConf, conf)
			}
			if err != nil {
				_ = packetConn.Close()
				return nil, err
			}
			return quicNetConn{Conn: quicConn, pc: packetConn}, nil
		})),
	)
	c, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, nil, err
	}
	nc := c.(quicNetConn)
	return nc.pc, nc.Conn, nil
}

type quicNetConn struct {
	*quic.Conn
	pc net.PacketConn
}

func (q quicNetConn) Close() error {
	err := q.Conn.CloseWithError(0, "")
	_ = q.pc.Close() // always close the packetConn
	return err
}

func (q quicNetConn) Read(b []byte) (n int, err error) {
	panic("should not call Read on quicNetConn")
}

func (q quicNetConn) Write(b []byte) (n int, err error) {
	panic("should not call Write on quicNetConn")
}

func (q quicNetConn) SetDeadline(t time.Time) error {
	panic("should not call SetDeadline on quicNetConn")
}

func (q quicNetConn) SetReadDeadline(t time.Time) error {
	panic("should not call SetReadDeadline on quicNetConn")
}

func (q quicNetConn) SetWriteDeadline(t time.Time) error {
	panic("should not call SetWriteDeadline on quicNetConn")
}

var _ net.Conn = quicNetConn{}
