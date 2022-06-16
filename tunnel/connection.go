package tunnel

import (
	"errors"
	"github.com/Dreamacro/clash/component/resolver"
	"net"
	"net/netip"
	"time"

	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
)

func handleUDPToRemote(packet C.UDPPacket, pc net.PacketConn, metadata *C.Metadata) error {
	pc = unwrapPacket(pc)

	defer packet.Drop()

	// local resolve UDP dns
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(metadata.Host)
		if err != nil {
			return err
		}
		metadata.DstIP = ip
	}

	addr := metadata.UDPAddr()
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(packet C.UDPPacket, pc net.PacketConn, key string, oAddr, fAddr netip.Addr) {
	pc = unwrapPacket(pc)

	buf := pool.Get(pool.UDPBufferSize)
	defer pool.Put(buf)
	defer natTable.Delete(key)
	defer pc.Close()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}

		fromUDPAddr := from.(*net.UDPAddr)
		if fAddr.IsValid() {
			fromAddr, _ := netip.AddrFromSlice(fromUDPAddr.IP)
			fromAddr.Unmap()
			if oAddr == fromAddr {
				fromUDPAddr.IP = fAddr.AsSlice()
			}
		}

		_, err = packet.WriteBack(buf[:n], fromUDPAddr)
		if err != nil {
			return
		}
	}
}

func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	left := unwrap(ctx.Conn())
	right := unwrap(outbound)

	if relayHijack(left, right) {
		return
	}

	N.Relay(left, right)
}
