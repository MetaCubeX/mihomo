//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"net/netip"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (t *Tun) deliverUDP(p []byte, info packetInfo, addr address) {
	length := int(binary.BigEndian.Uint16(p[info.offset+4:]))
	if length < 8 || info.offset+length > info.size {
		return
	}
	metadata := M.Metadata{Source: M.SocksaddrFromNetIP(info.source), Destination: M.SocksaddrFromNetIP(info.destination)}
	t.options.Handler.NewPacket(t.ctx, info.source, buf.As(p[info.offset+8:info.offset+length]).ToOwned(), metadata,
		func(N.PacketConn) N.PacketWriter {
			return &udpWriter{handle: t.handle, destination: info.source, addr: addr}
		})
}

type udpWriter struct {
	handle      *handle
	destination netip.AddrPort
	addr        address
}

func (w *udpWriter) WritePacket(buffer *buf.Buffer, source M.Socksaddr) error {
	defer buffer.Release()
	headerLen := 20
	if w.destination.Addr().Is6() {
		headerLen = 40
	}
	p := make([]byte, headerLen+8+buffer.Len())
	if headerLen == 20 {
		p[0], p[8], p[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		copy(p[12:16], source.Addr.AsSlice())
		copy(p[16:20], w.destination.Addr().AsSlice())
	} else {
		p[0], p[6], p[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
		copy(p[8:24], source.Addr.AsSlice())
		copy(p[24:40], w.destination.Addr().AsSlice())
	}
	binary.BigEndian.PutUint16(p[headerLen:], source.Port)
	binary.BigEndian.PutUint16(p[headerLen+2:], w.destination.Port())
	binary.BigEndian.PutUint16(p[headerLen+4:], uint16(8+buffer.Len()))
	copy(p[headerLen+8:], buffer.Bytes())
	_, err := w.handle.send(p, &w.addr)
	return err
}
