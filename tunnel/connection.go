package tunnel

import (
	"net"
	"time"

	cN "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, metadata *C.Metadata) error {
	defer packet.Data().Release()
	// local resolve UDP dns
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(metadata.Host)
		if err != nil {
			return err
		}
		metadata.DstIP = ip
	}

	if err := pc.WritePacket(packet.Data(), metadata.Socksaddr()); err != nil {
		return err
	}
	// reset timeout
	pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(packet C.UDPPacket, pc C.PacketConn, key string, fAddr net.Addr) {
	defer natTable.Delete(key)
	defer pc.Close()
	var fSocksaddr M.Socksaddr
	if fAddr != nil {
		fSocksaddr = M.SocksaddrFromNet(fAddr)
	}
	_, _ = copyPacketTimeout(packet, pc, udpTimeout, fSocksaddr, fAddr != nil)
}

func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	cN.Relay(ctx.Conn(), outbound)
}

func copyPacketTimeout(dst N.PacketWriter, src N.TimeoutPacketReader, timeout time.Duration, fAddr M.Socksaddr, fOverride bool) (n int64, err error) {
	_buffer := buf.StackNewPacket()
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	buffer.IncRef()
	defer buffer.DecRef()
	var destination M.Socksaddr
	for {
		buffer.Reset()
		err = src.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			return
		}
		destination, err = src.ReadPacket(buffer)
		if err != nil {
			return
		}
		if fOverride {
			destination = fAddr
		}
		dataLen := buffer.Len()
		err = dst.WritePacket(buffer, destination)
		if err != nil {
			return
		}
		n += int64(dataLen)
	}
}
