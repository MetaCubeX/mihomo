package outbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"

	vmess "github.com/metacubex/sing-vmess"
	vless "github.com/metacubex/sing-vmess/vless"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type xudpCaptureConn struct {
	bytes.Buffer
}

func (c *xudpCaptureConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (c *xudpCaptureConn) Close() error                    { return nil }
func (c *xudpCaptureConn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (c *xudpCaptureConn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (c *xudpCaptureConn) SetDeadline(time.Time) error     { return nil }
func (c *xudpCaptureConn) SetReadDeadline(time.Time) error { return nil }
func (c *xudpCaptureConn) SetWriteDeadline(time.Time) error {
	return nil
}

type xudpCaptureDialer struct {
	C.Dialer
	conn *xudpCaptureConn
}

func (d xudpCaptureDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func captureXUDPGlobalID(t *testing.T, kind, sessionKey string) []byte {
	t.Helper()
	const uuid = "885a0879-6292-41f3-84b6-9cfbbd17fd2d"
	raw := &xudpCaptureConn{}
	var proxy C.ProxyAdapter
	if kind == "VMess" {
		v, err := NewVmess(VmessOption{
			Name: "xudp_id", Server: "127.0.0.1", Port: 443, UUID: uuid,
			// The authenticated handshake is written while opening the connection.
			// A plain body lets this test inspect the actual encoded XUDP frame.
			Cipher: "none", UDP: true, PacketEncoding: "xudp",
		})
		require.NoError(t, err)
		v.dialer = xudpCaptureDialer{conn: raw}
		proxy = v
	} else {
		v, err := NewVless(VlessOption{
			Name: "xudp_id", Server: "127.0.0.1", Port: 443, UUID: uuid, UDP: true, PacketEncoding: "xudp",
		})
		require.NoError(t, err)
		v.dialer = xudpCaptureDialer{conn: raw}
		proxy = v
	}
	defer proxy.Close()
	target := M.ParseSocksaddr("192.0.2.2:443")
	metadata := &C.Metadata{
		NetWork: C.UDP, SrcIP: netip.MustParseAddr("192.0.2.1"), SrcPort: 30000,
		DstIP: target.Addr, DstPort: target.Port,
		UDP: &C.UDPRequest{Target: target, AllowRemote: true, SessionKey: sessionKey},
	}
	pc, err := proxy.ListenPacketContext(context.Background(), metadata)
	require.NoError(t, err)
	defer pc.Close()
	frameOffset := raw.Len()
	if kind == "VMess" {
		require.Positive(t, frameOffset, "the VMess handshake must precede the captured frame")
	}
	payload := []byte("xudp association identity")
	_, err = pc.WriteTo(payload, pc.InitialDestination())
	require.NoError(t, err)
	reader := bytes.NewReader(raw.Bytes()[frameOffset:])
	if kind == "VLESS" {
		request, err := vless.ReadRequest(reader)
		require.NoError(t, err)
		require.EqualValues(t, vmess.CommandMux, request.Command)
	}
	var headerLength uint16
	require.NoError(t, binary.Read(reader, binary.BigEndian, &headerLength))
	header := make([]byte, headerLength)
	_, err = io.ReadFull(reader, header)
	require.NoError(t, err)
	id := header[len(header)-8:]
	return id
}

func TestXUDPGlobalIDAssociationIdentity(t *testing.T) {
	for _, kind := range []string{"VMess", "VLESS"} {
		t.Run(kind, func(t *testing.T) {
			for _, origin := range []string{"198.18.0.1:443", "198.18.0.2:443"} {
				key := C.NewUDPSessionKey("tun:192.0.2.1:30000", C.UDPAddressAndPortDependent, M.ParseSocksaddr(origin)).String()
				want := utils.GlobalID(key)
				require.Equal(t, want[:], captureXUDPGlobalID(t, kind, key))
			}
		})
	}
}
