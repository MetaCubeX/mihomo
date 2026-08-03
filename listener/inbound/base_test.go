package inbound

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type recordingListenConfig struct {
	network string
	address string
}

func (c *recordingListenConfig) Listen(_ context.Context, network, address string) (net.Listener, error) {
	c.network = network
	c.address = address
	return net.Listen(network, address)
}

func (*recordingListenConfig) ListenPacket(_ context.Context, network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func unixSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mihomo-unix-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	return filepath.Join(dir, name)
}

func TestUnixSocketListenConfig(t *testing.T) {
	path := unixSocketPath(t, "mihomo.sock")
	recording := &recordingListenConfig{}
	base, err := newBase(&BaseOption{
		NameStr:            "unix-in",
		Port:               path,
		ListenConfigForAPI: recording,
	}, true)
	require.NoError(t, err)
	require.Equal(t, path, base.RawAddress())

	l, err := base.ListenConfig().Listen(context.Background(), "tcp", path)
	require.NoError(t, err)
	require.Equal(t, "unix", recording.network)
	require.Equal(t, path, recording.address)

	c, err := net.Dial("unix", path)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	require.NoError(t, l.Close())
	require.NoFileExists(t, path)
}

func TestUnixSocketBaseValidation(t *testing.T) {
	path := unixSocketPath(t, "mihomo.sock")

	_, err := NewBase(&BaseOption{Port: path})
	require.ErrorContains(t, err, "not supported")

	_, err = newBase(&BaseOption{Port: path, Listen: "127.0.0.1"}, true)
	require.ErrorContains(t, err, "listen cannot be used")

	_, err = newBase(&BaseOption{Port: path, RoutingMark: 1}, true)
	require.ErrorContains(t, err, "routing-mark cannot be used")

	_, err = newBase(&BaseOption{Port: "relative.sock"}, true)
	require.Error(t, err)
}

func TestUnixSocketInboundListeners(t *testing.T) {
	tests := []struct {
		name  string
		first byte
		new   func(BaseOption) (C.InboundListener, error)
	}{
		{
			name:  "http",
			first: 'G',
			new: func(base BaseOption) (C.InboundListener, error) {
				return NewHTTP(&HTTPOption{BaseOption: base})
			},
		},
		{
			name:  "socks",
			first: 5,
			new: func(base BaseOption) (C.InboundListener, error) {
				return NewSocks(&SocksOption{BaseOption: base})
			},
		},
		{
			name:  "mixed",
			first: 'G',
			new: func(base BaseOption) (C.InboundListener, error) {
				return NewMixed(&MixedOption{BaseOption: base})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := unixSocketPath(t, tt.name+".sock")
			l, err := tt.new(BaseOption{NameStr: tt.name, Port: path})
			require.NoError(t, err)
			require.NoError(t, l.Listen(nil))
			t.Cleanup(func() { require.NoError(t, l.Close()) })

			conn, err := net.Dial("unix", path)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(200*time.Millisecond)))
			_, err = conn.Write([]byte{tt.first})
			require.NoError(t, err)
			_, err = conn.Read(make([]byte, 1))
			netErr, ok := err.(net.Error)
			require.True(t, ok && netErr.Timeout(), "listener closed a UNIX peer: %v", err)
		})
	}
}

func TestUnixSocketProtocolInboundListenersBind(t *testing.T) {
	tests := []struct {
		name string
		new  func(BaseOption) (C.InboundListener, error)
	}{
		{name: "shadowsocks", new: func(base BaseOption) (C.InboundListener, error) {
			return NewShadowSocks(&ShadowSocksOption{BaseOption: base, Cipher: "aes-128-gcm", Password: "test"})
		}},
		{name: "snell", new: func(base BaseOption) (C.InboundListener, error) {
			return NewSnell(&SnellOption{BaseOption: base, Psk: "test"})
		}},
		{name: "vmess", new: func(base BaseOption) (C.InboundListener, error) {
			return NewVmess(&VmessOption{BaseOption: base, Users: []VmessUser{{UUID: "00000000-0000-0000-0000-000000000000"}}})
		}},
		{name: "trojan", new: func(base BaseOption) (C.InboundListener, error) {
			return NewTrojan(&TrojanOption{BaseOption: base, Users: []TrojanUser{{Password: "test"}}, AllowInsecure: true})
		}},
		{name: "anytls", new: func(base BaseOption) (C.InboundListener, error) {
			return NewAnyTLS(&AnyTLSOption{BaseOption: base, Users: map[string]string{"test": "test"}, AllowInsecure: true})
		}},
		{name: "sudoku", new: func(base BaseOption) (C.InboundListener, error) {
			return NewSudoku(&SudokuOption{BaseOption: base, Key: "test"})
		}},
		{name: "tunnel", new: func(base BaseOption) (C.InboundListener, error) {
			return NewTunnel(&TunnelOption{BaseOption: base, Network: []string{"tcp"}, Target: "127.0.0.1:80"})
		}},
		{name: "hysteria2-realm", new: func(base BaseOption) (C.InboundListener, error) {
			options := DefaultHysteria2RealmServerOption()
			options.BaseOption = base
			options.Token = "test"
			return NewHysteria2RealmServer(options)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := unixSocketPath(t, tt.name+".sock")
			l, err := tt.new(BaseOption{NameStr: tt.name, Port: path})
			require.NoError(t, err)
			require.NoError(t, l.Listen(nil))
			require.FileExists(t, path)
			require.NoError(t, l.Close())
			require.NoFileExists(t, path)
		})
	}
}
