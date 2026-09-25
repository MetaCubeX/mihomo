package sniffer

import (
	"encoding/hex"
	"net"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"

	"github.com/stretchr/testify/assert"
)

func newBitTorrentDispatcher(t *testing.T) *Dispatcher {
	t.Helper()

	sd, err := NewDispatcher(&Config{
		Enable:      true,
		ParsePureIp: true,
		Sniffers: map[snifferTypes.Type]SnifferConfig{
			snifferTypes.BitTorrent: {},
		},
	})
	assert.NoError(t, err)
	return sd
}

func TestDispatcherSeparatesProtocolSniffers(t *testing.T) {
	sd := newBitTorrentDispatcher(t)

	// a protocol sniffer must never end up in the domain list, otherwise it
	// would take part in the overrideDest election and hijack it
	assert.Len(t, sd.protocolSniffers, 1)
	assert.Len(t, sd.sniffers, 0)
}

func TestDispatcherTCPSniffProtocol(t *testing.T) {
	sd := newBitTorrentDispatcher(t)

	handshake, err := hex.DecodeString("13426974546f7272656e742070726f746f636f6c0000000000100000e21ea9569b69bab33c97851d0298bdfa89bc90922d5554313631302dea812fcd6a3563e3be40c1d1")
	assert.NoError(t, err)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write(handshake)
	}()

	metadata := &C.Metadata{NetWork: C.TCP, DstPort: 6881}
	conn := N.NewBufferedConn(server)

	// no domain was recovered, so TCPSniff still reports false
	assert.False(t, sd.TCPSniff(conn, metadata))
	assert.Equal(t, C.ProtocolBitTorrent, metadata.SniffProtocol)
	// the destination must be left untouched
	assert.Empty(t, metadata.Host)
	assert.Empty(t, metadata.SniffHost)
}

func TestDispatcherTCPSniffNotBitTorrent(t *testing.T) {
	sd := newBitTorrentDispatcher(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	metadata := &C.Metadata{NetWork: C.TCP, DstPort: 6881}
	conn := N.NewBufferedConn(server)

	assert.False(t, sd.TCPSniff(conn, metadata))
	assert.Empty(t, metadata.SniffProtocol)
}

func TestDispatcherUDPSniffProtocol(t *testing.T) {
	sd := newBitTorrentDispatcher(t)

	for name, payload := range map[string]string{
		"utp":     "21001ecb6817f2805d044fd700100000dbd03029",
		"tracker": "00000417271019800000000078e90560",
	} {
		data, err := hex.DecodeString(payload)
		assert.NoError(t, err)

		metadata := &C.Metadata{NetWork: C.UDP, DstPort: 6881}
		pkt := constantPacket(data, metadata)

		sender := sd.UDPSniff(pkt, &fakeSender{})
		// nothing to wait for, the verdict is taken from the first packet
		assert.NotNil(t, sender)
		assert.Equal(t, C.ProtocolBitTorrent, metadata.SniffProtocol, name)
	}
}

func TestDispatcherUDPSniffNotBitTorrent(t *testing.T) {
	sd := newBitTorrentDispatcher(t)

	metadata := &C.Metadata{NetWork: C.UDP, DstPort: 6881}
	pkt := constantPacket([]byte("just some udp payload that is long enough"), metadata)

	sd.UDPSniff(pkt, &fakeSender{})
	assert.Empty(t, metadata.SniffProtocol)
}

func constantPacket(data []byte, metadata *C.Metadata) C.PacketAdapter {
	pkt := &fakeUDPPacket{data: data, data2: append([]byte(nil), data...)}
	return C.NewPacketAdapter(pkt, metadata)
}
