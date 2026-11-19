package inbound_test

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMuxCool_V2RayInterop tests the Mux.Cool client against the reference server implementation.
func TestMuxCool_V2RayInterop(t *testing.T) {
	vmessInteropSkip(t)
	v2rayBin := vmessInteropV2RayBinary(t)

	startServer := func(t *testing.T, protocol string) int {
		v2rayPort := vmessInteropReserveTCPPort(t)
		config := vmessInteropBaseConfig()
		config["inbounds"] = []any{map[string]any{
			"protocol": protocol,
			"listen":   "127.0.0.1",
			"port":     v2rayPort.Port(),
			"settings": map[string]any{
				"users": []string{userUUID},
			},
		}}
		config["outbounds"] = []any{vmessInteropDirectOutbound()}
		startVMessInteropV2Ray(t, v2rayBin, vmessInteropMarshalJSONConfig(t, config), v2rayPort.Release,
			net.JoinHostPort("127.0.0.1", strconv.Itoa(v2rayPort.Port())))
		return v2rayPort.Port()
	}

	muxCoolOpts := outbound.MuxCoolOptions{Enabled: true, Concurrency: 4}
	doTest := func(t *testing.T, out C.ProxyAdapter) {
		echoAddr := startVMessInteropEcho(t)
		metadata := vmessInteropMetadata(t, echoAddr)

		// one after another on the same connection
		for i := 0; i < 3; i++ {
			conn, err := out.DialContext(context.Background(), metadata)
			require.NoError(t, err)
			assert.NoError(t, vmessInteropRoundTripConn(conn, 128*1024))
			assert.NoError(t, conn.Close())
		}

		// more sub connections than one connection can carry
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := out.DialContext(context.Background(), metadata)
				if !assert.NoError(t, err) {
					return
				}
				defer conn.Close()
				assert.NoError(t, vmessInteropRoundTripConn(conn, 128*1024))
			}()
		}
		wg.Wait()
	}

	t.Run("vmess", func(t *testing.T) {
		out, err := outbound.NewVmess(outbound.VmessOption{
			Name:        "vmess_muxcool_v2ray_server",
			Server:      "127.0.0.1",
			Port:        startServer(t, "vmess"),
			UUID:        userUUID,
			Cipher:      "auto",
			MuxCoolOpts: muxCoolOpts,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = out.Close() })
		doTest(t, out)
	})

	t.Run("vless", func(t *testing.T) {
		out, err := outbound.NewVless(outbound.VlessOption{
			Name:        "vless_muxcool_v2ray_server",
			Server:      "127.0.0.1",
			Port:        startServer(t, "vless"),
			UUID:        userUUID,
			MuxCoolOpts: muxCoolOpts,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = out.Close() })
		doTest(t, out)
	})
}
