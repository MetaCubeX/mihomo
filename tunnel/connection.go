package tunnel

import (
	"errors"
	"net"
	"net/netip"
	"time"

	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, metadata *C.Metadata) error {
	addr := metadata.UDPAddr()
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(packet C.UDPPacket, pc N.EnhancePacketConn, key string, oAddr, fAddr netip.Addr) {
	defer func() {
		_ = pc.Close()
		closeAllLocalCoon(key)
		natTable.Delete(key)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		data, put, from, err := pc.WaitReadFrom()
		if err != nil {
			return
		}

		fromUDPAddr := from.(*net.UDPAddr)
		_fromUDPAddr := *fromUDPAddr
		fromUDPAddr = &_fromUDPAddr // make a copy
		if fromAddr, ok := netip.AddrFromSlice(fromUDPAddr.IP); ok {
			if fAddr.IsValid() && (oAddr.Unmap() == fromAddr.Unmap()) {
				fromUDPAddr.IP = fAddr.Unmap().AsSlice()
			} else {
				fromUDPAddr.IP = fromAddr.Unmap().AsSlice()
			}
		}

		_, err = packet.WriteBack(data, fromUDPAddr)
		put()
		if err != nil {
			return
		}
	}
}

func closeAllLocalCoon(lAddr string) {
	natTable.RangeLocalConn(lAddr, func(key, value any) bool {
		conn, ok := value.(*net.UDPConn)
		if !ok || conn == nil {
			log.Debugln("Value %#v unknown value when closing TProxy local conn...", conn)
			return true
		}
		conn.Close()
		log.Debugln("Closing TProxy local conn... lAddr=%s rAddr=%s", lAddr, key)
		return true
	})
}

func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	N.Relay(ctx.Conn(), outbound)
}
