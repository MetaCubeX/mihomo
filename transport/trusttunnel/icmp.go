package trusttunnel

import (
	"encoding/binary"
	"net/netip"

	"github.com/metacubex/mihomo/common/buf"
)

type IcmpConn struct {
	httpConn
}

func (i *IcmpConn) WritePing(id uint16, destination netip.Addr, sequenceNumber uint16, ttl uint8, size uint16) error {
	request := buf.NewSize(2 + 16 + 2 + 1 + 2)
	defer request.Release()
	buf.Must(binary.Write(request, binary.BigEndian, id))
	destinationAddress := buildPaddingIP(destination)
	buf.Must1(request.Write(destinationAddress[:]))
	buf.Must(binary.Write(request, binary.BigEndian, sequenceNumber))
	buf.Must(binary.Write(request, binary.BigEndian, ttl))
	buf.Must(binary.Write(request, binary.BigEndian, size))
	return buf.Error(i.writeFlush(request.Bytes()))
}

func (i *IcmpConn) ReadPing() (id uint16, sourceAddress netip.Addr, icmpType uint8, code uint8, sequenceNumber uint16, err error) {
	err = i.waitCreated()
	if err != nil {
		return
	}
	response := buf.NewSize(2 + 16 + 1 + 1 + 2)
	defer response.Release()
	_, err = response.ReadFullFrom(i.body, response.Cap())
	if err != nil {
		return
	}
	buf.Must(binary.Read(response, binary.BigEndian, &id))
	var sourceAddressBuffer [16]byte
	buf.Must1(response.Read(sourceAddressBuffer[:]))
	sourceAddress = parse16BytesIP(sourceAddressBuffer)
	buf.Must(binary.Read(response, binary.BigEndian, &icmpType))
	buf.Must(binary.Read(response, binary.BigEndian, &code))
	buf.Must(binary.Read(response, binary.BigEndian, &sequenceNumber))
	return
}

func (i *IcmpConn) Close() error {
	return i.httpConn.Close()
}

func (i *IcmpConn) ReadPingRequest() (id uint16, destination netip.Addr, sequenceNumber uint16, ttl uint8, size uint16, err error) {
	err = i.waitCreated()
	if err != nil {
		return
	}
	request := buf.NewSize(2 + 16 + 2 + 1 + 2)
	defer request.Release()
	_, err = request.ReadFullFrom(i.body, request.Cap())
	if err != nil {
		return
	}
	buf.Must(binary.Read(request, binary.BigEndian, &id))
	var destinationAddressBuffer [16]byte
	buf.Must1(request.Read(destinationAddressBuffer[:]))
	destination = parse16BytesIP(destinationAddressBuffer)
	buf.Must(binary.Read(request, binary.BigEndian, &sequenceNumber))
	buf.Must(binary.Read(request, binary.BigEndian, &ttl))
	buf.Must(binary.Read(request, binary.BigEndian, &size))
	return
}

func (i *IcmpConn) WritePingResponse(id uint16, sourceAddress netip.Addr, icmpType uint8, code uint8, sequenceNumber uint16) error {
	response := buf.NewSize(2 + 16 + 1 + 1 + 2)
	defer response.Release()
	buf.Must(binary.Write(response, binary.BigEndian, id))
	sourceAddressBytes := buildPaddingIP(sourceAddress)
	buf.Must1(response.Write(sourceAddressBytes[:]))
	buf.Must(binary.Write(response, binary.BigEndian, icmpType))
	buf.Must(binary.Write(response, binary.BigEndian, code))
	buf.Must(binary.Write(response, binary.BigEndian, sequenceNumber))
	return buf.Error(i.writeFlush(response.Bytes()))
}
