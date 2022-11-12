package sing_tun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/listener/sing"
	"github.com/Dreamacro/clash/log"

	D "github.com/miekg/dns"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

const DefaultDnsReadTimeout = time.Second * 10
const DefaultDnsRelayTimeout = time.Second * 5

type ListenerHandler struct {
	sing.ListenerHandler
	DnsAdds []netip.AddrPort
}

func (h *ListenerHandler) ShouldHijackDns(targetAddr netip.AddrPort) bool {
	if targetAddr.Addr().IsLoopback() && targetAddr.Port() == 53 { // cause by system stack
		return true
	}
	for _, addrPort := range h.DnsAdds {
		if addrPort == targetAddr || (addrPort.Addr().IsUnspecified() && targetAddr.Port() == 53) {
			return true
		}
	}
	return false
}

func (h *ListenerHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if h.ShouldHijackDns(metadata.Destination.AddrPort()) {
		log.Debugln("[DNS] hijack tcp:%s", metadata.Destination.String())
		buff := pool.Get(pool.UDPBufferSize)
		defer func() {
			_ = pool.Put(buff)
			_ = conn.Close()
		}()
		for {
			if conn.SetReadDeadline(time.Now().Add(DefaultDnsReadTimeout)) != nil {
				break
			}

			length := uint16(0)
			if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
				break
			}

			if int(length) > len(buff) {
				break
			}

			n, err := io.ReadFull(conn, buff[:length])
			if err != nil {
				break
			}

			err = func() error {
				ctx, cancel := context.WithTimeout(ctx, DefaultDnsRelayTimeout)
				defer cancel()
				inData := buff[:n]
				msg, err := RelayDnsPacket(ctx, inData)
				if err != nil {
					return err
				}

				err = binary.Write(conn, binary.BigEndian, uint16(len(msg)))
				if err != nil {
					return err
				}

				_, err = conn.Write(msg)
				if err != nil {
					return err
				}
				return nil
			}()
			if err != nil {
				return err
			}
		}
		return nil
	}
	return h.ListenerHandler.NewConnection(ctx, conn, metadata)
}

func (h *ListenerHandler) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	if h.ShouldHijackDns(metadata.Destination.AddrPort()) {
		log.Debugln("[DNS] hijack udp:%s from %s", metadata.Destination.String(), metadata.Source.String())
		defer func() { _ = conn.Close() }()
		mutex := sync.Mutex{}
		conn2 := conn // a new interface to set nil in defer
		defer func() {
			mutex.Lock() // this goroutine must exit after all conn.WritePacket() is not running
			defer mutex.Unlock()
			conn2 = nil
		}()
		for {
			buff := buf.NewPacket()
			dest, err := conn.ReadPacket(buff)
			if err != nil {
				buff.Release()
				if E.IsClosed(err) {
					break
				}
				return err
			}
			go func() {
				ctx, cancel := context.WithTimeout(ctx, DefaultDnsRelayTimeout)
				defer cancel()
				inData := buff.Bytes()
				msg, err := RelayDnsPacket(ctx, inData)
				if err != nil {
					buff.Release()
					return
				}
				buff.Reset()
				_, err = buff.Write(msg)
				if err != nil {
					buff.Release()
					return
				}
				mutex.Lock()
				defer mutex.Unlock()
				conn := conn2
				if conn == nil {
					return
				}
				err = conn.WritePacket(buff, dest) // WritePacket will release buff
				if err != nil {
					return
				}
			}()
		}
		return nil
	}
	return h.ListenerHandler.NewPacketConnection(ctx, conn, metadata)
}

func RelayDnsPacket(ctx context.Context, payload []byte) ([]byte, error) {
	msg := &D.Msg{}
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}

	r, err := resolver.ServeMsg(ctx, msg)
	if err != nil {
		m := new(D.Msg)
		m.SetRcode(msg, D.RcodeServerFailure)
		return m.Pack()
	}

	r.SetRcode(msg, r.Rcode)
	r.Compress = true
	return r.Pack()
}
