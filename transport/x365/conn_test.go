package x365

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/metacubex/mihomo/common/buf"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testUUID = "c5f1a574-20a8-4f06-8880-2ae7a4af2f7e"

func TestRequestHeader(t *testing.T) {
	id := uuid.FromStringOrNil(testUUID)
	tests := []struct {
		name string
		dst  *DstAddr
		addr []byte
	}{
		{"ipv4", &DstAddr{AddrType: AtypIPv4, Addr: []byte{1, 2, 3, 4}, Port: 443}, []byte{AtypIPv4, 1, 2, 3, 4}},
		{"domain", &DstAddr{AddrType: AtypDomainName, Addr: append([]byte{11}, "example.com"...), Port: 80}, append([]byte{AtypDomainName, 11}, "example.com"...)},
		{"ipv6", &DstAddr{AddrType: AtypIPv6, Addr: net.ParseIP("2001:db8::1").To16(), Port: 8443}, append([]byte{AtypIPv6}, net.ParseIP("2001:db8::1").To16()...)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			conn := NewClient(testUUID).StreamConn(client, test.dst)
			payload := []byte("hello")
			go func() {
				_, _ = conn.Write(payload)
			}()

			want := []byte("X365")
			want = append(want, 0x01, 0x01) // version, TCP
			want = append(want, id.Bytes()...)
			want = append(want, byte(test.dst.Port>>8), byte(test.dst.Port))
			want = append(want, test.addr...)
			want = append(want, payload...)

			got := make([]byte, len(want))
			_, err := io.ReadFull(server, got)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		wantErr  bool
	}{
		{"ok", []byte("X365\x00payload"), false},
		{"bad magic", []byte("X366\x00payload"), true},
		{"rejected", []byte("X365\x01payload"), true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			conn := NewClient(testUUID).StreamConn(client, &DstAddr{AddrType: AtypIPv4, Addr: []byte{1, 2, 3, 4}, Port: 443})
			go func() {
				_, _ = server.Write(test.response)
				_ = server.Close()
			}()

			got, err := io.ReadAll(conn)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.True(t, bytes.Equal([]byte("payload"), got))
		})
	}
}

func TestFirstWriteBuffer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewClient(testUUID).StreamConn(client, &DstAddr{AddrType: AtypIPv4, Addr: []byte{1, 2, 3, 4}, Port: 443}).(*Conn)
	buffer := buf.New()
	buffer.Write([]byte("hello"))
	errCh := make(chan error, 1)
	go func() {
		errCh <- conn.WriteBuffer(buffer)
	}()

	got := make([]byte, 4+1+1+16+2+1+4+len("hello"))
	_, err := io.ReadFull(server, got)
	require.NoError(t, err)
	require.NoError(t, <-errCh)
	assert.Equal(t, []byte("hello"), got[len(got)-len("hello"):])
	assert.Zero(t, buffer.Cap(), "the first WriteBuffer must release the buffer it was given")
}
