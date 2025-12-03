package inbound_test

import (
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
)

func TestNewMieru(t *testing.T) {
	type args struct {
		option *inbound.MieruOption
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid with port",
			args: args{
				option: &inbound.MieruOption{
					BaseOption: inbound.BaseOption{
						Port: "8080",
					},
					Transport: "TCP",
					Users:     map[string]string{"user": "pass"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid with port range",
			args: args{
				option: &inbound.MieruOption{
					BaseOption: inbound.BaseOption{
						Port: "8090-8099",
					},
					Transport: "UDP",
					Users:     map[string]string{"user": "pass"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid mix of port and port-range",
			args: args{
				option: &inbound.MieruOption{
					BaseOption: inbound.BaseOption{
						Port: "8080,8090-8099",
					},
					Transport: "TCP",
					Users:     map[string]string{"user": "pass"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid - no port",
			args: args{
				option: &inbound.MieruOption{
					Transport: "TCP",
					Users:     map[string]string{"user": "pass"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid - transport",
			args: args{
				option: &inbound.MieruOption{
					BaseOption: inbound.BaseOption{
						Port: "8080",
					},
					Transport: "INVALID",
					Users:     map[string]string{"user": "pass"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid - no transport",
			args: args{
				option: &inbound.MieruOption{
					BaseOption: inbound.BaseOption{
						Port: "8080",
					},
					Users: map[string]string{"user": "pass"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid - no users",
			args: args{
				option: &inbound.MieruOption{
					BaseOption: inbound.BaseOption{
						Port: "8080",
					},
					Transport: "TCP",
					Users:     map[string]string{},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid - empty username",
			args: args{
				option: &inbound.MieruOption{
					BaseOption: inbound.BaseOption{
						Port: "8080",
					},
					Transport: "TCP",
					Users:     map[string]string{"": "pass"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid - empty password",
			args: args{
				option: &inbound.MieruOption{
					BaseOption: inbound.BaseOption{
						Port: "8080",
					},
					Transport: "TCP",
					Users:     map[string]string{"user": ""},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := inbound.NewMieru(tt.args.option)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMieru() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				got.Close()
			}
		})
	}
}

func TestInboundMieru(t *testing.T) {
	t.Run("TCP_HANDSHAKE_STANDARD", func(t *testing.T) {
		testInboundMieruTCP(t, "HANDSHAKE_STANDARD")
	})
	t.Run("TCP_HANDSHAKE_NO_WAIT", func(t *testing.T) {
		testInboundMieruTCP(t, "HANDSHAKE_NO_WAIT")
	})
	t.Run("UDP_HANDSHAKE_STANDARD", func(t *testing.T) {
		testInboundMieruUDP(t, "HANDSHAKE_STANDARD")
	})
	t.Run("UDP_HANDSHAKE_NO_WAIT", func(t *testing.T) {
		testInboundMieruUDP(t, "HANDSHAKE_NO_WAIT")
	})
}

func testInboundMieruTCP(t *testing.T, handshakeMode string) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	inboundOptions := inbound.MieruOption{
		BaseOption: inbound.BaseOption{
			NameStr: "mieru_inbound_tcp",
			Listen:  "127.0.0.1",
			Port:    strconv.Itoa(port),
		},
		Transport: "TCP",
		Users:     map[string]string{"test": "password"},
	}
	in, err := inbound.NewMieru(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}
	outboundOptions := outbound.MieruOption{
		Name:          "mieru_outbound_tcp",
		Server:        addrPort.Addr().String(),
		Port:          int(addrPort.Port()),
		Transport:     "TCP",
		UserName:      "test",
		Password:      "password",
		HandshakeMode: handshakeMode,
	}
	out, err := outbound.NewMieru(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func testInboundMieruUDP(t *testing.T, handshakeMode string) {
	t.Parallel()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()

	inboundOptions := inbound.MieruOption{
		BaseOption: inbound.BaseOption{
			NameStr: "mieru_inbound_udp",
			Listen:  "127.0.0.1",
			Port:    strconv.Itoa(port),
		},
		Transport: "UDP",
		Users:     map[string]string{"test": "password"},
	}
	in, err := inbound.NewMieru(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}
	outboundOptions := outbound.MieruOption{
		Name:          "mieru_outbound_udp",
		Server:        addrPort.Addr().String(),
		Port:          int(addrPort.Port()),
		Transport:     "UDP",
		UserName:      "test",
		Password:      "password",
		HandshakeMode: handshakeMode,
	}
	out, err := outbound.NewMieru(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoSequentialTest(t, out)
}
