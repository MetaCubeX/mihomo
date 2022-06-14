package tunnel

import (
	"errors"
	"net"
	"time"

	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
)

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, metadata *C.Metadata) error {
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
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(packet C.UDPPacket, pc net.PacketConn, key string, fAddr net.Addr) {
	buf := pool.Get(pool.UDPBufferSize)
	defer func() {
		_ = pc.Close()
		natTable.Delete(key)
		_ = pool.Put(buf)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}

		if fAddr != nil {
			from = fAddr
		}

		_, err = packet.WriteBack(buf[:n], from)
		if err != nil {
			return
		}
	}
}

func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	N.Relay(ctx.Conn(), outbound)
}
