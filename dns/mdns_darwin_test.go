//go:build darwin

package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mdnsResponderTestRequest struct {
	flags    uint32
	iface    uint32
	protocol uint32
	hostname string
}

func startMDNSResponderTestServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()

	socketDir, err := os.MkdirTemp("", "mihomo-mdns-")
	require.NoError(t, err)
	socketPath := filepath.Join(socketDir, "socket")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.RemoveAll(socketDir)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fake mDNSResponder did not stop")
		}
	})
	return socketPath
}

func readMDNSResponderTestRequest(t *testing.T, conn net.Conn) mdnsResponderTestRequest {
	t.Helper()

	header := make([]byte, mdnsResponderHeaderSize)
	_, err := io.ReadFull(conn, header)
	require.NoError(t, err)
	require.Equal(t, uint32(mdnsResponderIPCVersion), binary.BigEndian.Uint32(header[0:4]))
	require.Equal(t, uint32(mdnsResponderAddrInfoOp), binary.BigEndian.Uint32(header[12:16]))
	body := make([]byte, binary.BigEndian.Uint32(header[4:8]))
	_, err = io.ReadFull(conn, body)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(body), 13)
	require.Zero(t, body[len(body)-1])
	return mdnsResponderTestRequest{
		flags:    binary.BigEndian.Uint32(body[0:4]),
		iface:    binary.BigEndian.Uint32(body[4:8]),
		protocol: binary.BigEndian.Uint32(body[8:12]),
		hostname: string(body[12 : len(body)-1]),
	}
}

func writeMDNSResponderTestInitialError(t *testing.T, conn net.Conn, code int32) {
	t.Helper()
	var data [4]byte
	binary.BigEndian.PutUint32(data[:], uint32(code))
	require.NoError(t, writeAll(conn, data[:]))
}

func writeMDNSResponderTestReply(t *testing.T, conn net.Conn, name string, rrType uint16, rdata net.IP, ttl uint32) {
	t.Helper()

	if rrType == D.TypeA {
		rdata = rdata.To4()
	} else {
		rdata = rdata.To16()
	}
	dataLength := mdnsResponderReplyHeader + len(name) + 1 + 3*2 + len(rdata) + 4
	message := make([]byte, mdnsResponderHeaderSize+dataLength)
	binary.BigEndian.PutUint32(message[0:4], mdnsResponderIPCVersion)
	binary.BigEndian.PutUint32(message[4:8], uint32(dataLength))
	binary.BigEndian.PutUint32(message[12:16], mdnsResponderAddrInfoReply)
	body := message[mdnsResponderHeaderSize:]
	binary.BigEndian.PutUint32(body[0:4], mdnsResponderFlagAdd)
	binary.BigEndian.PutUint32(body[4:8], 25)
	offset := mdnsResponderReplyHeader
	copy(body[offset:], name)
	offset += len(name) + 1
	binary.BigEndian.PutUint16(body[offset:offset+2], rrType)
	binary.BigEndian.PutUint16(body[offset+2:offset+4], D.ClassINET)
	binary.BigEndian.PutUint16(body[offset+4:offset+6], uint16(len(rdata)))
	offset += 6
	copy(body[offset:], rdata)
	offset += len(rdata)
	binary.BigEndian.PutUint32(body[offset:offset+4], ttl)
	require.NoError(t, writeAll(conn, message))
}

func newMDNSResponderTestClient(t *testing.T, socketPath string) *mdnsClient {
	t.Helper()
	t.Setenv("DNSSD_UDS_PATH", socketPath)
	client := newMDNSClient()
	client.timeout = 300 * time.Millisecond
	client.settle = 20 * time.Millisecond
	client.targets = func() ([]mdnsTarget, error) {
		return nil, errors.New("unexpected portable multicast fallback")
	}
	return client
}

func TestMDNSResponderUnavailableFallsBack(t *testing.T) {
	client := newMDNSResponderTestClient(t, filepath.Join(t.TempDir(), "missing"))

	response, handled, err := client.exchangeMDNSPlatform(context.Background(), mdnsQuery("host.local", D.TypeA))
	assert.Nil(t, response)
	assert.False(t, handled)
	assert.NoError(t, err)
}

func TestMDNSResponderAAndAAAA(t *testing.T) {
	tests := []struct {
		name       string
		qtype      uint16
		protocol   uint32
		ip         net.IP
		expectedIP string
	}{
		{name: "A", qtype: D.TypeA, protocol: mdnsResponderProtocolIPv4, ip: net.IPv4(192, 0, 2, 30), expectedIP: "192.0.2.30"},
		{name: "AAAA", qtype: D.TypeAAAA, protocol: mdnsResponderProtocolIPv6, ip: net.ParseIP("2001:db8::30"), expectedIP: "2001:db8::30"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			socketPath := startMDNSResponderTestServer(t, func(conn net.Conn) {
				request := readMDNSResponderTestRequest(t, conn)
				assert.Equal(t, uint32(mdnsResponderForceMulticast), request.flags)
				assert.Zero(t, request.iface)
				assert.Equal(t, test.protocol, request.protocol)
				assert.Equal(t, "host.local.", request.hostname)
				writeMDNSResponderTestInitialError(t, conn, 0)
				writeMDNSResponderTestReply(t, conn, "host.local.", test.qtype, test.ip, 300)
				_, _ = io.Copy(io.Discard, conn)
			})
			client := newMDNSResponderTestClient(t, socketPath)

			response, err := client.ExchangeContext(context.Background(), mdnsQuery("host.local", test.qtype))
			require.NoError(t, err)
			require.Len(t, response.Answer, 1)
			assert.Equal(t, uint32(300), response.Answer[0].Header().Ttl)
			switch answer := response.Answer[0].(type) {
			case *D.A:
				assert.Equal(t, test.expectedIP, answer.A.String())
			case *D.AAAA:
				assert.Equal(t, test.expectedIP, answer.AAAA.String())
			default:
				t.Fatalf("unexpected answer type %T", answer)
			}
		})
	}
}

func TestMDNSResponderMergesMultipleResponses(t *testing.T) {
	socketPath := startMDNSResponderTestServer(t, func(conn net.Conn) {
		_ = readMDNSResponderTestRequest(t, conn)
		writeMDNSResponderTestInitialError(t, conn, 0)
		writeMDNSResponderTestReply(t, conn, "multi.local.", D.TypeA, net.IPv4(192, 0, 2, 1), 60)
		writeMDNSResponderTestReply(t, conn, "multi.local.", D.TypeA, net.IPv4(192, 0, 2, 2), 120)
		_, _ = io.Copy(io.Discard, conn)
	})
	client := newMDNSResponderTestClient(t, socketPath)

	response, err := client.ExchangeContext(context.Background(), mdnsQuery("multi.local", D.TypeA))
	require.NoError(t, err)
	assert.Len(t, response.Answer, 2)
}

func TestMDNSResponderTimeout(t *testing.T) {
	socketPath := startMDNSResponderTestServer(t, func(conn net.Conn) {
		_ = readMDNSResponderTestRequest(t, conn)
		writeMDNSResponderTestInitialError(t, conn, 0)
		_, _ = io.Copy(io.Discard, conn)
	})
	client := newMDNSResponderTestClient(t, socketPath)
	client.timeout = 50 * time.Millisecond

	_, err := client.ExchangeContext(context.Background(), mdnsQuery("silent.local", D.TypeA))
	assert.ErrorIs(t, err, errMDNSTimeout)
}

func TestMDNSResponderContextCancellation(t *testing.T) {
	queryReceived := make(chan struct{})
	socketPath := startMDNSResponderTestServer(t, func(conn net.Conn) {
		_ = readMDNSResponderTestRequest(t, conn)
		writeMDNSResponderTestInitialError(t, conn, 0)
		close(queryReceived)
		_, _ = io.Copy(io.Discard, conn)
	})
	client := newMDNSResponderTestClient(t, socketPath)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.ExchangeContext(ctx, mdnsQuery("cancel.local", D.TypeA))
		result <- err
	}()

	<-queryReceived
	cancel()
	select {
	case err := <-result:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("mDNSResponder query did not stop after context cancellation")
	}
}

func TestMDNSResponderCloseReleasesSocket(t *testing.T) {
	queryReceived := make(chan struct{})
	socketPath := startMDNSResponderTestServer(t, func(conn net.Conn) {
		_ = readMDNSResponderTestRequest(t, conn)
		writeMDNSResponderTestInitialError(t, conn, 0)
		close(queryReceived)
		_, _ = io.Copy(io.Discard, conn)
	})
	client := newMDNSResponderTestClient(t, socketPath)
	client.timeout = time.Second
	result := make(chan error, 1)
	go func() {
		_, err := client.ExchangeContext(context.Background(), mdnsQuery("close.local", D.TypeA))
		result <- err
	}()

	<-queryReceived
	require.Eventually(t, func() bool { return client.activeSockets() == 1 }, time.Second, 10*time.Millisecond)
	require.NoError(t, client.Close())
	select {
	case err := <-result:
		assert.ErrorIs(t, err, errMDNSClientClosed)
	case <-time.After(time.Second):
		t.Fatal("mDNSResponder query did not stop after client close")
	}
	assert.Eventually(t, func() bool { return client.activeSockets() == 0 }, time.Second, 10*time.Millisecond)
}
