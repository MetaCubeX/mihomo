package v5

import (
	"bytes"
	"io"
	"net"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/tuic/types"

	M "github.com/metacubex/sing/common/metadata"
)

type wireConn struct {
	net.Conn
	io.Reader
}

func (c *wireConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }
func TestNativeUDPReplyAddresses(t *testing.T) {
	for _, tc := range []struct {
		target     string
		fragmented bool
	}{
		{"remote-only.invalid:1234", false},
		{"192.0.2.1:1234", false},
		{"[2001:db8::1]:1234", false},
		{"remote-only.invalid:1234", true},
	} {
		target := tc.target
		for _, wait := range []bool{false, true} {
			address, err := NewAddressNetAddr(M.ParseSocksaddr(target))
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			fragments := []string{"response"}
			if tc.fragmented {
				fragments = []string{"res", "ponse"}
			}
			for i, data := range fragments {
				packet := NewPacket(1, 2, uint8(len(fragments)), uint8(i), uint16(len(data)), address, []byte(data))
				if err = packet.WriteTo(&wire); err != nil {
					t.Fatal(err)
				}
				address = Address{TYPE: AtypNone}
			}
			pc := &quicStreamPacketConn{udpRelayMode: types.NATIVE, inputConn: N.NewBufferedConn(&wireConn{Reader: bytes.NewReader(wire.Bytes())})}
			var data []byte
			var from net.Addr
			if wait {
				data, _, from, err = pc.WaitReadFrom()
			} else {
				data = make([]byte, 1024)
				var n int
				n, from, err = pc.ReadFrom(data)
				data = data[:n]
			}
			if err != nil {
				t.Fatal(err)
			}
			if from == nil || from.String() != target || string(data) != "response" {
				t.Fatalf("decoded reply: %v %q", from, data)
			}
			if target == "remote-only.invalid:1234" && !M.SocksaddrFromNet(from).IsFqdn() {
				t.Fatal("lost domain")
			}
		}
	}
}
