//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/mipstack"
	tun "github.com/metacubex/sing-tun"
)

// stackDevice adapts captured IP packets to sing-tun's device contract.
type stackDevice struct {
	tun     *Tun
	packets chan []byte
}

var _ tun.WinTun = (*stackDevice)(nil)

func (t *Tun) startMIPS() error {
	device := &stackDevice{tun: t, packets: make(chan []byte, batchSize)}
	ipStack, err := tun.NewStack("mips", tun.StackOptions{
		Context: t.ctx, Tun: device, TunOptions: tun.Options{MTU: t.options.MTU},
		UDPTimeout: t.options.UDPTimeout, Handler: t.options.Handler, Logger: log.SingLogger,
	})
	if err != nil {
		return err
	}
	t.closeStack = func() { _ = device.Close(); _ = ipStack.Close() }
	if err := ipStack.Start(); err != nil {
		return err
	}
	t.deliver = func(p []byte, info packetInfo, _ address) { device.deliver(p[:info.size]) }
	return nil
}

func (d *stackDevice) deliver(p []byte) {
	owned := pool.Get(len(p))
	copy(owned, p)
	select {
	case d.packets <- owned:
	case <-d.tun.ctx.Done():
		_ = pool.Put(owned)
	}
}

func (d *stackDevice) ReadPacket() ([]byte, func(), error) {
	if d.tun.ctx.Err() != nil {
		return nil, nil, net.ErrClosed
	}
	select {
	case p := <-d.packets:
		return p, func() { _ = pool.Put(p) }, nil
	case <-d.tun.ctx.Done():
		return nil, nil, net.ErrClosed
	}
}

func (d *stackDevice) Read(p []byte) (int, error) {
	packet, release, err := d.ReadPacket()
	if err != nil {
		return 0, err
	}
	defer release()
	if len(p) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, packet), nil
}

func (d *stackDevice) Write(p []byte) (int, error) {
	addr, ok := d.tun.responseInterface(packetDestination(p))
	if !ok {
		return 0, net.ErrClosed
	}
	addr.Flags = flagIPChecksum | flagTCPChecksum | flagUDPChecksum
	owned := pool.Get(len(p))
	copy(owned, p)
	if err := d.tun.queuePacket(owned, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *stackDevice) Close() error {
	for {
		select {
		case p := <-d.packets:
			_ = pool.Put(p)
		default:
			return nil
		}
	}
}

func completeChecksums(p []byte, info packetInfo, flags uint32) {
	// Windows can leave the IPv4 checksum zero even with IPChecksum set.
	if info.source.Addr().Is4() && (flags&flagIPChecksum == 0 || binary.BigEndian.Uint16(p[10:]) == 0) {
		p[10], p[11] = 0, 0
		binary.BigEndian.PutUint16(p[10:], mipstack.InternetChecksum(p[:info.offset]))
	}
	payload := p[info.offset:info.size]
	checksumOffset, checksumFlag := 16, uint32(flagTCPChecksum)
	if info.protocol == 17 {
		length := int(binary.BigEndian.Uint16(payload[4:]))
		payload = payload[:length]
		checksumOffset, checksumFlag = 6, flagUDPChecksum
	}
	if flags&checksumFlag == 0 {
		payload[checksumOffset], payload[checksumOffset+1] = 0, 0
		checksum, _ := mipstack.IPTransportChecksum(info.source.Addr(), info.destination.Addr(), int(info.protocol), payload)
		if info.protocol == 17 && checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(payload[checksumOffset:], checksum)
	}
}
