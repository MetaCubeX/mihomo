package reality

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	proxyproto "github.com/pires/go-proxyproto"
)

func TestWriteProxyProtocolHeaderDisabled(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if err := writeProxyProtocolHeader(context.Background(), client, 0); err != nil {
		t.Fatalf("writeProxyProtocolHeader() error = %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	buf := make([]byte, 1)
	_, err := server.Read(buf)
	if err == nil {
		t.Fatal("expected no payload when proxy-protocol is disabled")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected timeout read error, got %v", err)
	}
}

func TestWriteProxyProtocolHeader(t *testing.T) {
	tests := []struct {
		name              string
		version           int
		source            net.Addr
		destination       net.Addr
		wantCommand       proxyproto.ProtocolVersionAndCommand
		wantTransport     proxyproto.AddressFamilyAndProtocol
		wantSource        string
		wantSourcePort    int
		wantDestination   string
		wantDestPort      int
		wantVersion1Bytes []byte
	}{
		{
			name:            "v1 tcp4",
			version:         1,
			source:          &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
			destination:     &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443},
			wantCommand:     proxyproto.PROXY,
			wantTransport:   proxyproto.TCPv4,
			wantSource:      "192.0.2.1",
			wantSourcePort:  12345,
			wantDestination: "198.51.100.2",
			wantDestPort:    443,
		},
		{
			name:            "v2 tcp4",
			version:         2,
			source:          &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4567},
			destination:     &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 8443},
			wantCommand:     proxyproto.PROXY,
			wantTransport:   proxyproto.TCPv4,
			wantSource:      "192.0.2.10",
			wantSourcePort:  4567,
			wantDestination: "198.51.100.20",
			wantDestPort:    8443,
		},
		{
			name:            "v1 tcp6",
			version:         1,
			source:          &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 12345},
			destination:     &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443},
			wantCommand:     proxyproto.PROXY,
			wantTransport:   proxyproto.TCPv6,
			wantSource:      "2001:db8::1",
			wantSourcePort:  12345,
			wantDestination: "2001:db8::2",
			wantDestPort:    443,
		},
		{
			name:            "v2 tcp6",
			version:         2,
			source:          &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 4567},
			destination:     &net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 8443},
			wantCommand:     proxyproto.PROXY,
			wantTransport:   proxyproto.TCPv6,
			wantSource:      "2001:db8::10",
			wantSourcePort:  4567,
			wantDestination: "2001:db8::20",
			wantDestPort:    8443,
		},
		{
			name:              "v1 mismatched families degrade to unknown",
			version:           1,
			source:            &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
			destination:       &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443},
			wantCommand:       proxyproto.LOCAL,
			wantTransport:     proxyproto.UNSPEC,
			wantVersion1Bytes: []byte("PROXY UNKNOWN\r\n"),
		},
		{
			name:          "v2 mismatched families degrade to unspec",
			version:       2,
			source:        &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
			destination:   &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443},
			wantCommand:   proxyproto.LOCAL,
			wantTransport: proxyproto.UNSPEC,
		},
		{
			name:              "v1 non-tcp addresses degrade to unknown",
			version:           1,
			source:            pipeAddr("source"),
			destination:       pipeAddr("destination"),
			wantCommand:       proxyproto.LOCAL,
			wantTransport:     proxyproto.UNSPEC,
			wantVersion1Bytes: []byte("PROXY UNKNOWN\r\n"),
		},
		{
			name:          "v2 non-tcp addresses degrade to unspec",
			version:       2,
			source:        pipeAddr("source"),
			destination:   pipeAddr("destination"),
			wantCommand:   proxyproto.LOCAL,
			wantTransport: proxyproto.UNSPEC,
		},
		{
			name:              "v1 invalid ip degrades to unknown",
			version:           1,
			source:            &net.TCPAddr{Port: 12345},
			destination:       &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443},
			wantCommand:       proxyproto.LOCAL,
			wantTransport:     proxyproto.UNSPEC,
			wantVersion1Bytes: []byte("PROXY UNKNOWN\r\n"),
		},
		{
			name:          "v2 invalid port degrades to unspec",
			version:       2,
			source:        &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 70000},
			destination:   &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443},
			wantCommand:   proxyproto.LOCAL,
			wantTransport: proxyproto.UNSPEC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := writeHeaderToBuffer(t, tt.version, tt.source, tt.destination)
			if tt.wantVersion1Bytes != nil && !bytes.Equal(payload, tt.wantVersion1Bytes) {
				t.Fatalf("unexpected v1 header: got %q want %q", payload, tt.wantVersion1Bytes)
			}

			header, err := proxyproto.Read(bufio.NewReader(bytes.NewReader(payload)))
			if err != nil {
				t.Fatalf("proxyproto.Read() error = %v", err)
			}
			assertProxyProtocolHeader(t, header, byte(tt.version), tt.wantCommand, tt.wantTransport, tt.wantSource, tt.wantSourcePort, tt.wantDestination, tt.wantDestPort)
		})
	}
}

func TestWriteProxyProtocolHeaderMissingAddressesDegradesToUnknown(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	headerCh := make(chan *proxyproto.Header, 1)
	errCh := make(chan error, 1)
	go readProxyProtocolHeader(server, headerCh, errCh)

	if err := writeProxyProtocolHeader(context.Background(), client, 1); err != nil {
		t.Fatalf("writeProxyProtocolHeader() error = %v", err)
	}

	header := receiveProxyProtocolHeader(t, headerCh, errCh)
	assertProxyProtocolHeader(t, header, 1, proxyproto.LOCAL, proxyproto.UNSPEC, "", 0, "", 0)
}

func TestWriteProxyProtocolHeaderInvalidVersion(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	ctx = context.WithValue(ctx, sourceAddrContextKey{}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345})
	ctx = context.WithValue(ctx, destinationAddrContextKey{}, &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443})

	err := writeProxyProtocolHeader(ctx, client, 3)
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func TestConfigBuildInvalidProxyProtocol(t *testing.T) {
	config := Config{ProxyProtocol: 3}

	_, err := config.Build(nil)
	if err == nil {
		t.Fatal("expected error for invalid proxy-protocol value")
	}
}

func TestConfigBuildDialContextWritesProxyProtocolHeader(t *testing.T) {
	tests := []struct {
		name            string
		proxyProtocol   int
		source          net.Addr
		destination     net.Addr
		wantCommand     proxyproto.ProtocolVersionAndCommand
		wantTransport   proxyproto.AddressFamilyAndProtocol
		wantSource      string
		wantSourcePort  int
		wantDestination string
		wantDestPort    int
	}{
		{
			name:            "v2 tcp4",
			proxyProtocol:   2,
			source:          &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
			destination:     &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443},
			wantCommand:     proxyproto.PROXY,
			wantTransport:   proxyproto.TCPv4,
			wantSource:      "192.0.2.1",
			wantSourcePort:  12345,
			wantDestination: "198.51.100.2",
			wantDestPort:    443,
		},
		{
			name:          "v1 missing addresses degrade to unknown",
			proxyProtocol: 1,
			wantCommand:   proxyproto.LOCAL,
			wantTransport: proxyproto.UNSPEC,
		},
		{
			name:          "v2 mismatched families degrade to unspec",
			proxyProtocol: 2,
			source:        &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
			destination:   &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443},
			wantCommand:   proxyproto.LOCAL,
			wantTransport: proxyproto.UNSPEC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tunnel := &captureTunnel{
				headerCh: make(chan *proxyproto.Header, 1),
				errCh:    make(chan error, 1),
			}
			config := Config{
				Dest:          "example.com:443",
				PrivateKey:    testRealityPrivateKey(t),
				ProxyProtocol: tt.proxyProtocol,
			}
			builder, err := config.Build(tunnel)
			if err != nil {
				t.Fatalf("Config.Build() error = %v", err)
			}

			ctx := context.Background()
			if tt.source != nil {
				ctx = context.WithValue(ctx, sourceAddrContextKey{}, tt.source)
			}
			if tt.destination != nil {
				ctx = context.WithValue(ctx, destinationAddrContextKey{}, tt.destination)
			}

			conn, err := builder.realityConfig.DialContext(ctx, "tcp", "example.com:443")
			if err != nil {
				t.Fatalf("DialContext() error = %v", err)
			}
			defer conn.Close()

			header := receiveProxyProtocolHeader(t, tunnel.headerCh, tunnel.errCh)
			assertProxyProtocolHeader(t, header, byte(tt.proxyProtocol), tt.wantCommand, tt.wantTransport, tt.wantSource, tt.wantSourcePort, tt.wantDestination, tt.wantDestPort)
		})
	}
}

func TestNewListenerWritesProxyProtocolHeaderFromAcceptedConnection(t *testing.T) {
	tunnel := &captureTunnel{
		headerCh: make(chan *proxyproto.Header, 1),
		errCh:    make(chan error, 1),
	}
	config := Config{
		Dest:          "example.com:443",
		PrivateKey:    testRealityPrivateKey(t),
		ProxyProtocol: 2,
	}
	builder, err := config.Build(tunnel)
	if err != nil {
		t.Fatalf("Config.Build() error = %v", err)
	}

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	listener := builder.NewListener(rawListener)
	defer listener.Close()

	acceptErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		acceptErrCh <- err
	}()

	client, err := net.Dial("tcp", rawListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	header := receiveProxyProtocolHeader(t, tunnel.headerCh, tunnel.errCh)
	sourceAddr := client.LocalAddr().(*net.TCPAddr)
	destinationAddr := client.RemoteAddr().(*net.TCPAddr)
	wantTransport := proxyproto.TCPv4
	if sourceAddr.IP.To4() == nil {
		wantTransport = proxyproto.TCPv6
	}
	assertProxyProtocolHeader(t, header, 2, proxyproto.PROXY, wantTransport, sourceAddr.IP.String(), sourceAddr.Port, destinationAddr.IP.String(), destinationAddr.Port)

	_ = listener.Close()
	select {
	case <-acceptErrCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Accept() to exit")
	}
}

func writeHeaderToBuffer(t *testing.T, version int, source, destination net.Addr) []byte {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	ctx = context.WithValue(ctx, sourceAddrContextKey{}, source)
	ctx = context.WithValue(ctx, destinationAddrContextKey{}, destination)

	payloadCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		_, err := io.Copy(&buf, server)
		if err != nil {
			errCh <- err
			return
		}
		payloadCh <- buf.Bytes()
	}()

	if err := writeProxyProtocolHeader(ctx, client, version); err != nil {
		t.Fatalf("writeProxyProtocolHeader() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("read header error: %v", err)
	case payload := <-payloadCh:
		return payload
	case <-time.After(time.Second):
		t.Fatal("timed out reading proxy-protocol header")
	}
	return nil
}

func assertProxyProtocolHeader(t *testing.T, header *proxyproto.Header, version byte, command proxyproto.ProtocolVersionAndCommand, transport proxyproto.AddressFamilyAndProtocol, source string, sourcePort int, destination string, destinationPort int) {
	t.Helper()

	if header.Version != version {
		t.Fatalf("header version = %d, want %d", header.Version, version)
	}
	if header.Command != command {
		t.Fatalf("header command = %#x, want %#x", header.Command, command)
	}
	if header.TransportProtocol != transport {
		t.Fatalf("header transport = %#x, want %#x", header.TransportProtocol, transport)
	}
	if command == proxyproto.LOCAL || transport == proxyproto.UNSPEC {
		return
	}

	sourceTCPAddr, destinationTCPAddr, ok := header.TCPAddrs()
	if !ok {
		t.Fatal("expected TCP addresses")
	}
	if got := sourceTCPAddr.IP.String(); got != source {
		t.Fatalf("source IP = %s, want %s", got, source)
	}
	if sourceTCPAddr.Port != sourcePort {
		t.Fatalf("source port = %d, want %d", sourceTCPAddr.Port, sourcePort)
	}
	if got := destinationTCPAddr.IP.String(); got != destination {
		t.Fatalf("destination IP = %s, want %s", got, destination)
	}
	if destinationTCPAddr.Port != destinationPort {
		t.Fatalf("destination port = %d, want %d", destinationTCPAddr.Port, destinationPort)
	}
}

func testRealityPrivateKey(t *testing.T) string {
	t.Helper()

	privateKey := []byte("0123456789abcdef0123456789abcdef")
	return base64.RawURLEncoding.EncodeToString(privateKey)
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

type captureTunnel struct {
	headerCh chan *proxyproto.Header
	errCh    chan error
}

func (t *captureTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	readProxyProtocolHeader(conn, t.headerCh, t.errCh)
}

func (t *captureTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}

func (t *captureTunnel) NatTable() C.NatTable { return nil }

var _ C.Tunnel = (*captureTunnel)(nil)

func readProxyProtocolHeader(conn net.Conn, headerCh chan<- *proxyproto.Header, errCh chan<- error) {
	header, err := proxyproto.Read(bufio.NewReader(conn))
	if err != nil {
		errCh <- err
		return
	}
	headerCh <- header
}

func receiveProxyProtocolHeader(t *testing.T, headerCh <-chan *proxyproto.Header, errCh <-chan error) *proxyproto.Header {
	t.Helper()

	select {
	case header := <-headerCh:
		return header
	case err := <-errCh:
		t.Fatalf("read proxy-protocol header error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out reading proxy-protocol header")
	}
	return nil
}
