package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

type Dns struct {
	*Base
}

type DnsOption struct {
	BasicOption
	Name string `proxy:"name"`
}

// DialContext implements C.ProxyAdapter
func (d *Dns) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	return nil, fmt.Errorf("dns outbound does not support tcp")
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Dns) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	log.Debugln("[DNS] hijack udp:%s from %s", metadata.RemoteAddress(), metadata.SourceAddrPort())

	return newPacketConn(&dnsPacketConn{
		response:    make(chan []byte),
		doneReading: make(chan int),
	}, d), nil
}

// dnsPacketConn implements net.PacketConn
type dnsPacketConn struct {
	response    chan []byte
	writeTo     net.Addr
	doneReading chan int
}

func (d *dnsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := <-d.response

	log.Debugln("[DNS] hijack ReadFrom, len %d", len(buf))

	if buf != nil {
		n := copy(p, buf)
		return n, d.writeTo, nil
	}

	return 0, nil, fmt.Errorf("read from closed dns packet conn")
}

func (d *dnsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	log.Debugln("[DNS] hijack WriteTo %s, len %d", addr.String(), len(p))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	buf, err := RelayDnsPacket(ctx, p, make([]byte, 4096))
	if err != nil {
		log.Warnln("[DNS] dns hijack: relay dns packet: %s", err)
		return 0, err
	}

	d.writeTo = addr
	d.response <- buf

	return len(p), nil
}

func (d *dnsPacketConn) Close() error {
	close(d.response)
	return nil
}

func (*dnsPacketConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:53"))
}

func (*dnsPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (*dnsPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (*dnsPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func NewDnsWithOption(option DnsOption) *Dns {
	return &Dns{
		Base: &Base{
			name:   option.Name,
			tp:     C.Direct,
			udp:    true,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
	}
}

// copied from listener/sing_mux/dns.go
func RelayDnsPacket(ctx context.Context, payload []byte, target []byte) ([]byte, error) {
	msg := &D.Msg{}
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}

	r, err := resolver.ServeMsg(ctx, msg)
	if err != nil {
		m := new(D.Msg)
		m.SetRcode(msg, D.RcodeServerFailure)
		return m.PackBuffer(target)
	}

	r.SetRcode(msg, r.Rcode)
	r.Compress = true
	return r.PackBuffer(target)
}

func NewDns() *Dns {
	return &Dns{
		Base: &Base{
			name:   "DNS",
			tp:     C.Dns,
			udp:    true,
			prefer: C.DualStack,
		},
	}
}
