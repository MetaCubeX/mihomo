package sing_tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type echoTestWriter chan []byte

func (w echoTestWriter) WritePacket(p []byte) error { w <- append([]byte(nil), p...); return nil }

func echoTestRequest(v6 bool) ([]byte, netip.Addr, netip.Addr) {
	src, dst := netip.MustParseAddr("192.168.123.50"), netip.MustParseAddr("100.106.164.73")
	var typ icmp.Type = ipv4.ICMPTypeEcho
	headerLen := 20
	var pseudo []byte
	if v6 {
		src, dst = netip.MustParseAddr("fd12::50"), netip.MustParseAddr("fd7a:115c:a1e0::1")
		typ, headerLen = ipv6.ICMPTypeEchoRequest, 40
		pseudo = icmp.IPv6PseudoHeader(src.AsSlice(), dst.AsSlice())
	}
	m := icmp.Message{Type: typ, Body: &icmp.Echo{ID: 12345, Seq: 23456, Data: []byte("original payload 123")}}
	p, _ := m.Marshal(pseudo)
	b := make([]byte, headerLen+len(p))
	if v6 {
		b[0], b[6], b[7] = 0x60, 58, 64
		binary.BigEndian.PutUint16(b[4:6], uint16(len(p)))
		copy(b[8:24], src.AsSlice())
		copy(b[24:40], dst.AsSlice())
	} else {
		b[0], b[8], b[9] = 0x45, 64, 1
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		copy(b[12:16], src.AsSlice())
		copy(b[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(b[10:12], icmpInternetChecksum(b[:20]))
	}
	copy(b[headerLen:], p)
	return b, src, dst
}

func TestICMPEchoReply(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		packet, src, dst := echoTestRequest(v6)
		reply, err := icmpEchoReply(packet, src, dst)
		if err != nil {
			t.Fatal(err)
		}
		offset, protocol := 20, 1
		var expected icmp.Type = ipv4.ICMPTypeEchoReply
		if v6 {
			offset, protocol, expected = 40, 58, ipv6.ICMPTypeEchoReply
			if !bytes.Equal(reply[8:24], dst.AsSlice()) || !bytes.Equal(reply[24:40], src.AsSlice()) {
				t.Fatal("IPv6 addresses not reversed")
			}
			pseudo := icmp.IPv6PseudoHeader(dst.AsSlice(), src.AsSlice())
			binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(reply)-40))
			if icmpInternetChecksum(append(pseudo, reply[40:]...)) != 0 {
				t.Fatal("invalid ICMPv6 checksum")
			}
		} else {
			if !bytes.Equal(reply[12:16], dst.AsSlice()) || !bytes.Equal(reply[16:20], src.AsSlice()) {
				t.Fatal("IPv4 addresses not reversed")
			}
			if icmpInternetChecksum(reply[:20]) != 0 || icmpInternetChecksum(reply[20:]) != 0 {
				t.Fatal("invalid IPv4/ICMP checksum")
			}
		}
		m, err := icmp.ParseMessage(protocol, reply[offset:])
		if err != nil {
			t.Fatal(err)
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok || m.Type != expected || echo.ID != 12345 || echo.Seq != 23456 || string(echo.Data) != "original payload 123" {
			t.Fatalf("unexpected reply: %#v", m)
		}
		for _, bad := range [][]byte{packet[:10], packet[:len(packet)-1], reply} {
			if _, err := icmpEchoReply(bad, src, dst); err == nil {
				t.Fatal("accepted truncated or non-request packet")
			}
		}
		if _, err := icmpEchoReply(packet, dst, src); err == nil {
			t.Fatal("accepted another flow's packet")
		}
	}
}

func TestICMPEchoRequiresSuccessfulProbe(t *testing.T) {
	for _, success := range []bool{false, true} {
		packet, src, dst := echoTestRequest(false)
		writer := make(echoTestWriter, 1)
		started, allow := make(chan struct{}), make(chan struct{})
		d := newICMPEchoDestination(src, dst, writer, time.Second, func(ctx context.Context, target netip.Addr) error {
			if target != dst {
				t.Errorf("wrong target %s", target)
			}
			close(started)
			select {
			case <-allow:
			case <-ctx.Done():
				return ctx.Err()
			}
			if !success {
				return errors.New("offline")
			}
			return nil
		})
		b := buf.As(packet)
		if err := d.WritePacket(b); err != nil {
			t.Fatal(err)
		}
		<-started
		select {
		case <-writer:
			t.Fatal("replied before a probe succeeded")
		default:
		}
		// The input belongs to TUN and can be reused as soon as WritePacket returns.
		for i := range packet {
			packet[i] = 0
		}
		close(allow)
		if success {
			select {
			case reply := <-writer:
				m, _ := icmp.ParseMessage(1, reply[20:])
				if m.Body.(*icmp.Echo).ID != 12345 {
					t.Fatal("retained released TUN buffer")
				}
			case <-time.After(time.Second):
				t.Fatal("missing successful reply")
			}
		} else {
			select {
			case <-writer:
				t.Fatal("offline target received a fabricated reply")
			case <-time.After(30 * time.Millisecond):
			}
		}
		d.Close()
	}
}

func TestICMPEchoCancellationAndLimit(t *testing.T) {
	packet, src, dst := echoTestRequest(false)
	writer := make(echoTestWriter, 1)
	started, finished := make(chan struct{}, 16), make(chan struct{}, 16)
	d := newICMPEchoDestination(src, dst, writer, time.Second, func(ctx context.Context, _ netip.Addr) error {
		started <- struct{}{}
		<-ctx.Done()
		finished <- struct{}{}
		return ctx.Err()
	})
	for i := 0; i < 40; i++ {
		if err := d.WritePacket(buf.As(packet)); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.pending) != 16 {
		t.Fatalf("unbounded pending requests: %d", len(d.pending))
	}
	for i := 0; i < 16; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("probe not started")
		}
	}
	d.Close()
	for i := 0; i < 16; i++ {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("close did not cancel probe")
		}
	}
	if !d.IsClosed() {
		t.Fatal("still open")
	}
	select {
	case <-writer:
		t.Fatal("reply after cancellation")
	default:
	}
}

func TestICMPEchoIdleTimeout(t *testing.T) {
	packet, src, dst := echoTestRequest(true)
	finished := make(chan struct{})
	d := newICMPEchoDestination(src, dst, make(echoTestWriter, 1), 30*time.Millisecond, func(ctx context.Context, _ netip.Addr) error { <-ctx.Done(); close(finished); return ctx.Err() })
	defer d.Close()
	if err := d.WritePacket(buf.As(packet)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("probe did not time out")
	}
}
