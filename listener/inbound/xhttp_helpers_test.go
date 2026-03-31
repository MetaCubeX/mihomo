package inbound_test

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	adapterInbound "github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	listenerInbound "github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/listener/sing"
	listenerSingVless "github.com/metacubex/mihomo/listener/sing_vless"
	"github.com/metacubex/mihomo/transport/socks5"
	transportTrojan "github.com/metacubex/mihomo/transport/trojan"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type testXHTTPFrontendOption struct {
	Path        string
	Host        string
	Mode        string
	BackendAddr string
	UseHTTP3    bool
}

type testSharedXHTTPFrontend struct {
	handler http.Handler
}

// These helpers provide a local xhttp frontend so outbound xhttp modes can be
// exercised against existing protocol backends without Docker / external cores.
func startTestXHTTPFrontend(t *testing.T, option testXHTTPFrontendOption) string {
	t.Helper()

	handler := xhttp.NewServerHandler(xhttp.ServerOption{
		Path: option.Path,
		Host: option.Host,
		Mode: option.Mode,
		ConnHandler: func(conn net.Conn) {
			backendConn, err := net.Dial("tcp", option.BackendAddr)
			if err != nil {
				_ = conn.Close()
				return
			}
			N.Relay(conn, backendConn)
		},
	})

	return startTestXHTTPServer(t, handler, option.UseHTTP3)
}

func startTestSharedXHTTPFrontends(t *testing.T, backendAddr string, mode string, options ...testXHTTPFrontendOption) []string {
	t.Helper()

	frontend := &testSharedXHTTPFrontend{
		handler: xhttp.NewServerHandler(xhttp.ServerOption{
			Path: "/",
			Mode: mode,
			ConnHandler: func(conn net.Conn) {
				backendConn, err := net.Dial("tcp", backendAddr)
				if err != nil {
					_ = conn.Close()
					return
				}
				N.Relay(conn, backendConn)
			},
		}),
	}

	addrs := make([]string, len(options))
	for idx, option := range options {
		addrs[idx] = frontend.startAlias(t, option)
	}

	return addrs
}

func (f *testSharedXHTTPFrontend) startAlias(t *testing.T, option testXHTTPFrontendOption) string {
	t.Helper()

	return startTestXHTTPServer(t, wrapTestXHTTPAliasHandler(f.handler, option), option.UseHTTP3)
}

func startTestXHTTPServer(t *testing.T, handler http.Handler, useHTTP3 bool) string {
	t.Helper()

	if useHTTP3 {
		packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}

		server := &http3.Server{
			Handler:   handler,
			TLSConfig: http3.ConfigureTLSConfig(tlsConfig.Clone()),
		}
		go func() {
			_ = server.Serve(packetConn)
		}()

		t.Cleanup(func() {
			_ = server.Close()
			_ = packetConn.Close()
		})

		return packetConn.LocalAddr().String()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := &http.Server{Handler: handler}
	tlsListener := tls.NewListener(ln, tlsConfig.Clone())
	go func() {
		_ = server.Serve(tlsListener)
	}()

	t.Cleanup(func() {
		_ = server.Close()
		_ = tlsListener.Close()
	})

	return ln.Addr().String()
}

func wrapTestXHTTPAliasHandler(inner http.Handler, option testXHTTPFrontendOption) http.Handler {
	path := option.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if option.Host != "" && !equalTestXHTTPHost(r.Host, option.Host) {
			http.NotFound(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, path) {
			http.NotFound(w, r)
			return
		}

		cloned := r.Clone(r.Context())
		suffix := strings.TrimPrefix(r.URL.Path, path)
		if suffix == "" {
			cloned.URL.Path = "/"
		} else {
			cloned.URL.Path = "/" + suffix
		}
		cloned.RequestURI = ""

		inner.ServeHTTP(w, cloned)
	})
}

func equalTestXHTTPHost(a string, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	if ah, _, err := net.SplitHostPort(a); err == nil {
		a = ah
	}
	if bh, _, err := net.SplitHostPort(b); err == nil {
		b = bh
	}

	return a == b
}

func startTestVMessBackend(t *testing.T, tunnel *TestTunnel) string {
	t.Helper()

	in, err := listenerInbound.NewVmess(&listenerInbound.VmessOption{
		BaseOption: listenerInbound.BaseOption{
			NameStr: "vmess_xhttp_backend",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users: []listenerInbound.VmessUser{
			{Username: "test", UUID: userUUID, AlterID: 0},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := in.Listen(tunnel); err != nil {
		_ = in.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = in.Close()
	})

	return in.Address()
}

func startTestVlessBackend(t *testing.T, tunnel *TestTunnel) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	additions := []adapterInbound.Addition{
		adapterInbound.WithInName("DEFAULT-VLESS"),
		adapterInbound.WithSpecialRules(""),
	}
	handler, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.VLESS,
		Additions: additions,
	})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}

	service := listenerSingVless.NewService[string](handler)
	service.UpdateUsers([]string{"test"}, []string{userUUID}, []string{""})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go handleTestVlessConn(conn, service, additions)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
	})

	return ln.Addr().String()
}

func handleTestVlessConn(conn net.Conn, service *listenerSingVless.Service[string], additions []adapterInbound.Addition) {
	ctx := sing.WithAdditions(context.TODO(), additions...)
	err := service.NewConnection(ctx, conn, M.Metadata{
		Protocol: "vless",
		Source:   M.SocksaddrFromNet(conn.RemoteAddr()),
	})
	if err != nil {
		_ = conn.Close()
	}
}

func startTestTrojanBackend(t *testing.T, tunnel *TestTunnel, password string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	passwordKey := transportTrojan.Key(password)
	handler, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel: tunnel,
		Type:   C.TROJAN,
		Additions: []adapterInbound.Addition{
			adapterInbound.WithInName("DEFAULT-TROJAN"),
			adapterInbound.WithSpecialRules(""),
		},
	})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go handleTestTrojanConn(conn, handler, passwordKey)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
	})

	return ln.Addr().String()
}

func handleTestTrojanConn(conn net.Conn, handler *sing.ListenerHandler, passwordKey [transportTrojan.KeyLength]byte) {
	closeConn := true
	defer func() {
		if closeConn {
			_ = conn.Close()
		}
	}()

	var key [transportTrojan.KeyLength]byte
	if _, err := io.ReadFull(conn, key[:]); err != nil {
		return
	}
	if key != passwordKey {
		return
	}

	var crlf [2]byte
	if _, err := io.ReadFull(conn, crlf[:]); err != nil {
		return
	}
	if crlf != [2]byte{'\r', '\n'} {
		return
	}

	command, err := socks5.ReadByte(conn)
	if err != nil {
		return
	}
	if command != transportTrojan.CommandTCP {
		return
	}

	target, err := socks5.ReadAddr0(conn)
	if err != nil {
		return
	}

	if _, err := io.ReadFull(conn, crlf[:]); err != nil {
		return
	}
	if crlf != [2]byte{'\r', '\n'} {
		return
	}

	closeConn = false
	handler.HandleSocket(target, conn)
}
