package inbound_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/kcptun"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/metacubex/sing-shadowsocks/shadowstream"
	"github.com/stretchr/testify/assert"
)

var noneList = []string{shadowsocks.MethodNone}
var shadowsocksCipherLists = [][]string{noneList, shadowaead.List, shadowaead_2022.List, shadowstream.List}
var shadowsocksCipherShortLists = [][]string{noneList, shadowaead.List[:5]} // for test shadowTLS and kcptun
var shadowsocksPassword32 string
var shadowsocksPassword16 string

func init() {
	passwordBytes := make([]byte, 32)
	rand.Read(passwordBytes)
	shadowsocksPassword32 = base64.StdEncoding.EncodeToString(passwordBytes)
	shadowsocksPassword16 = base64.StdEncoding.EncodeToString(passwordBytes[:16])
}

func testInboundShadowSocks(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption, cipherLists [][]string, enableSingMux bool) {
	t.Parallel()
	for _, cipherList := range cipherLists {
		for i, cipher := range cipherList {
			enableSingMux := enableSingMux && i == 0
			cipher := cipher
			t.Run(cipher, func(t *testing.T) {
				inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
				inboundOptions.Cipher = cipher
				outboundOptions.Cipher = cipher
				testInboundShadowSocks0(t, inboundOptions, outboundOptions, enableSingMux)
			})
		}
	}
}

func testInboundShadowSocks0(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption, enableSingMux bool) {
	t.Parallel()
	password := shadowsocksPassword32
	if strings.Contains(inboundOptions.Cipher, "-128-") {
		password = shadowsocksPassword16
	}
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "shadowsocks_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Password = password
	in, err := inbound.NewShadowSocks(&inboundOptions)
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

	outboundOptions.Name = "shadowsocks_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = password
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err := outbound.NewShadowSocks(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)

	if enableSingMux {
		testSingMux(t, tunnel, out)
	}
}

func TestInboundShadowSocks_Basic(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{}
	outboundOptions := outbound.ShadowSocksOption{}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherLists, true)
}

func testInboundShadowSocksUTLS(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption, enableSingMux bool) {
	t.Parallel()
	t.Run("Conn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, enableSingMux)
	})
	t.Run("UConn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		outboundOptions.ClientFingerprint = "chrome"
		testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, enableSingMux)
	})
}

func TestInboundShadowSocks_ShadowTlsv1(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   1,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "fingerprint": tlsFingerprint, "version": 1},
	}
	testInboundShadowSocksUTLS(t, inboundOptions, outboundOptions, true)
}

func TestInboundShadowSocks_ShadowTlsv2(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   2,
			Password:  shadowsocksPassword16,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 2},
	}
	outboundOptions.PluginOpts["alpn"] = []string{"http/1.1"} // shadowtls v2 work confuse with http/2 server, so we set alpn to http/1.1 to pass the test
	testInboundShadowSocksUTLS(t, inboundOptions, outboundOptions, true)
}

func TestInboundShadowSocks_ShadowTlsv3(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: shadowsocksPassword16}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 3},
	}
	testInboundShadowSocksUTLS(t, inboundOptions, outboundOptions, true)
}

func TestInboundShadowSocks_Restls_tls12(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: shadowsocksPassword16,
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     restls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version-hint": "tls12", "force-tls12": true},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}

func TestInboundShadowSocks_Restls_tls13(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: shadowsocksPassword16,
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     restls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version-hint": "tls13"},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}

func TestInboundShadowSocks_JLS(t *testing.T) {
	username := "jls-user"
	password := "jls-password"
	inboundOptions := inbound.ShadowSocksOption{
		JLSConfig: inbound.JLSConfig{
			Enable: true,
			Users:  []inbound.JLSUser{{Username: username, Password: password}},
			SNI:    realityDest,
			Dest:   net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin: jls.Mode,
		PluginOpts: map[string]any{
			"host":     realityDest,
			"username": username,
			"password": password,
		},
	}
	testInboundShadowSocksUTLS(t, inboundOptions, outboundOptions, false)
}

func TestInboundShadowSocks_SimpleObfs_Http(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		SimpleObfs: inbound.SimpleObfs{
			Enable: true,
			Mode:   "http",
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     "obfs",
		PluginOpts: map[string]any{"mode": "http", "host": realityDest},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}

func TestInboundShadowSocks_SimpleObfs_Tls(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		SimpleObfs: inbound.SimpleObfs{
			Enable: true,
			Mode:   "tls",
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     "obfs",
		PluginOpts: map[string]any{"mode": "tls", "host": realityDest},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}

var shadowsocksMultiUserCipherList = append(append([]string{}, shadowaead.List...),
	"2022-blake3-aes-128-gcm",
	"2022-blake3-aes-256-gcm",
	"2022-blake3-aes-128-ccm",
	"2022-blake3-aes-256-ccm",
)

func newShadowSocksKey(cipher string) string {
	keyBytes := make([]byte, 32)
	if strings.Contains(cipher, "-128-") {
		keyBytes = keyBytes[:16]
	}
	rand.Read(keyBytes)
	return base64.StdEncoding.EncodeToString(keyBytes)
}

func TestInboundShadowSocks_Users(t *testing.T) {
	t.Parallel()
	for _, cipher := range shadowsocksMultiUserCipherList {
		cipher := cipher
		t.Run(cipher, func(t *testing.T) {
			t.Parallel()
			testInboundShadowSocksUsers(t, cipher)
		})
	}
}

func testInboundShadowSocksUsers(t *testing.T, cipher string) {
	is2022 := strings.HasPrefix(cipher, "2022-")
	var serverPassword string
	if is2022 {
		serverPassword = newShadowSocksKey(cipher)
	}
	users := map[string]string{
		"user1": newShadowSocksKey(cipher),
		"user2": newShadowSocksKey(cipher),
	}
	inboundOptions := inbound.ShadowSocksOption{
		BaseOption: inbound.BaseOption{
			NameStr: "shadowsocks_inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Password: serverPassword,
		Users:    users,
		Cipher:   cipher,
	}
	in, err := inbound.NewShadowSocks(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	var inUsers []string
	var inUsersMu sync.Mutex
	handleTCPConn := tunnel.HandleTCPConnFn
	tunnel.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
		inUsersMu.Lock()
		inUsers = append(inUsers, metadata.InUser)
		inUsersMu.Unlock()
		handleTCPConn(conn, metadata)
	}
	takeInUsers := func() []string {
		inUsersMu.Lock()
		defer inUsersMu.Unlock()
		users := inUsers
		inUsers = nil
		return users
	}

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	newOutbound := func(password string) (*outbound.ShadowSocks, error) {
		if is2022 {
			password = serverPassword + ":" + password
		}
		outboundOptions := outbound.ShadowSocksOption{
			Name:     "shadowsocks_outbound",
			Server:   addrPort.Addr().String(),
			Port:     int(addrPort.Port()),
			Password: password,
			Cipher:   cipher,
		}
		outboundOptions.DialerForAPI = tunnel.NewDialer()
		outboundOptions.TunnelForAPI = tunnel
		return outbound.NewShadowSocks(outboundOptions)
	}

	for username, password := range users {
		username, password := username, password
		t.Run(username, func(t *testing.T) {
			out, err := newOutbound(password)
			if !assert.NoError(t, err) {
				return
			}
			defer out.Close()

			tunnel.DoTest(t, out)

			inUsers := takeInUsers()
			assert.NotEmpty(t, inUsers)
			for _, inUser := range inUsers {
				assert.Equal(t, username, inUser)
			}
		})
	}

	t.Run("UnknownUser", func(t *testing.T) {
		out, err := newOutbound(newShadowSocksKey(cipher))
		if !assert.NoError(t, err) {
			return
		}
		defer out.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n"))
			_, err = conn.Read(make([]byte, 1))
			_ = conn.Close()
		}
		assert.Error(t, err)
		assert.Empty(t, takeInUsers())
	})
}

func TestInboundShadowSocks_MissingPassword(t *testing.T) {
	t.Parallel()
	for _, cipher := range []string{shadowsocks.MethodNone, shadowaead.List[0], shadowaead_2022.List[0], shadowstream.List[0]} {
		_, err := inbound.NewShadowSocks(&inbound.ShadowSocksOption{
			BaseOption: inbound.BaseOption{
				NameStr: "shadowsocks_inbound",
				Listen:  "127.0.0.1",
				Port:    "0",
			},
			Cipher: cipher,
		})
		assert.Error(t, err, cipher)
	}
}

func TestInboundShadowSocks_UsersInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cipher   string
		password string
		users    map[string]string
	}{
		{"None", shadowsocks.MethodNone, "", map[string]string{"user1": "password"}},
		{"Stream", shadowstream.List[0], "", map[string]string{"user1": "password"}},
		{"2022Chacha20", "2022-blake3-chacha20-poly1305", shadowsocksPassword32, map[string]string{"user1": shadowsocksPassword32}},
		{"2022MissingServerPassword", "2022-blake3-aes-128-gcm", "", map[string]string{"user1": shadowsocksPassword16}},
		{"2022ShortUserKey", "2022-blake3-aes-256-gcm", shadowsocksPassword32, map[string]string{"user1": shadowsocksPassword16}},
		{"AEADWithPassword", "aes-128-gcm", "password", map[string]string{"user1": "password1"}},
		{"AEADEmptyUserPassword", "aes-128-gcm", "", map[string]string{"user1": ""}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			in, err := inbound.NewShadowSocks(&inbound.ShadowSocksOption{
				BaseOption: inbound.BaseOption{
					NameStr: "shadowsocks_inbound",
					Listen:  "127.0.0.1",
					Port:    "0",
				},
				Password: test.password,
				Users:    test.users,
				Cipher:   test.cipher,
			})
			if !assert.NoError(t, err) {
				return
			}
			err = in.Listen(nil)
			if !assert.Error(t, err) {
				_ = in.Close()
			}
		})
	}
}

func TestInboundShadowSocks_KcpTun(t *testing.T) {
	if winGo120 {
		t.Skip("skip kcptun test on windows go1.20")
	}
	inboundOptions := inbound.ShadowSocksOption{
		KcpTun: inbound.KcpTun{
			Enable: true,
			Key:    shadowsocksPassword16,
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     kcptun.Mode,
		PluginOpts: map[string]any{"key": shadowsocksPassword16},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}
