package inbound_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"

	"github.com/stretchr/testify/require"
)

const (
	xrayRealityPlainUUID  = "73c1a1d8-6f4b-4b64-94f7-87a15fcdfe93"
	xrayRealityVisionUUID = "a4c6475a-c27d-43d9-b9b5-21ec8e5f67bc"
	xrayRealityShortID    = "0123456789abcdef"
)

func TestVLESSRealityXrayInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at a current Xray-core executable")
	}
	versionOutput, err := exec.Command(xrayBinary, "version").CombinedOutput()
	require.NoError(t, err, "xray version: %s", versionOutput)
	t.Logf("Xray executable: %s\n%s", xrayBinary, versionOutput)

	origin := startTLSMirrorInteropCarrierTLS(t, padRealityCarrierCertificate)
	echoAddr := startVMessInteropEcho(t)
	xrayPort := vmessInteropReserveTCPPort(t)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	mldsa65Seed := make([]byte, 32)
	mldsa65Seed[0] = 1
	_, mldsa65Verify, err := utls.RealityMldsa65KeyFromSeed(mldsa65Seed)
	require.NoError(t, err)

	config := xrayRealityServerConfig(t, xrayPort.Port(), origin.addr, privateKey, mldsa65Seed)
	startXrayRealityServer(t, xrayBinary, config, xrayPort)

	testCases := []struct {
		name              string
		uuid              string
		flow              string
		clientFingerprint string
		mldsa65Verify     []byte
	}{
		{
			name: "tcp empty fingerprint",
			uuid: xrayRealityPlainUUID,
		},
		{
			name:              "vision chrome auto",
			uuid:              xrayRealityVisionUUID,
			flow:              "xtls-rprx-vision",
			clientFingerprint: "chrome",
		},
		{
			name:              "chrome auto X25519MLKEM768 and ML-DSA-65",
			uuid:              xrayRealityPlainUUID,
			clientFingerprint: "chrome",
			mldsa65Verify:     mldsa65Verify,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			out, err := outbound.NewVless(outbound.VlessOption{
				Name:              "vless_reality_xray",
				Server:            "127.0.0.1",
				Port:              xrayPort.Port(),
				UUID:              testCase.uuid,
				Flow:              testCase.flow,
				TLS:               true,
				ServerName:        "localhost",
				ClientFingerprint: testCase.clientFingerprint,
				RealityOpts: outbound.RealityOptions{
					PublicKey:     base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
					ShortID:       xrayRealityShortID,
					Mldsa65Verify: base64.RawURLEncoding.EncodeToString(testCase.mldsa65Verify),
					Show:          testCase.mldsa65Verify != nil,
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			vmessInteropRoundTripWithRetry(t, func() (net.Conn, error) {
				return out.DialContext(context.Background(), vmessInteropMetadata(t, echoAddr))
			}, 128*1024)
		})
	}
}

func TestVLESSRealityXrayClientToMihomoServer(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at a current Xray-core executable")
	}
	origin := startTLSMirrorInteropCarrierTLS(t, padRealityCarrierCertificate)
	echoAddr := startVMessInteropEcho(t)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	mldsa65Seed := make([]byte, 32)
	mldsa65Seed[0] = 2
	_, mldsa65Verify, err := utls.RealityMldsa65KeyFromSeed(mldsa65Seed)
	require.NoError(t, err)

	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption: inbound.BaseOption{NameStr: "vless_reality_xray_client", Listen: "127.0.0.1", Port: "0"},
		Users:      []inbound.VlessUser{{Username: "xray", UUID: xrayRealityPlainUUID}},
		RealityConfig: inbound.RealityConfig{
			Dest:        origin.addr,
			PrivateKey:  base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
			ShortID:     []string{xrayRealityShortID},
			ServerNames: []string{"localhost"},
			Mldsa65Seed: base64.RawURLEncoding.EncodeToString(mldsa65Seed),
			Show:        true,
		},
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(vmessInteropDirectTunnel(t)))
	t.Cleanup(func() { _ = in.Close() })
	mihomoPort := vmessInteropParsePort(t, vmessInteropPort(in.Address()))

	xrayPort := vmessInteropReserveTCPPort(t)
	config := xrayRealityClientConfig(t, xrayPort.Port(), mihomoPort, echoAddr, privateKey.PublicKey().Bytes(), mldsa65Verify)
	startXrayRealityServer(t, xrayBinary, config, xrayPort)

	vmessInteropRoundTripWithRetry(t, func() (net.Conn, error) {
		return net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(xrayPort.Port())))
	}, 128*1024)
}

func xrayRealityClientConfig(t *testing.T, listenPort, serverPort int, targetAddr string, publicKey, mldsa65Verify []byte) []byte {
	t.Helper()
	targetHost, targetPort, err := net.SplitHostPort(targetAddr)
	require.NoError(t, err)
	targetPortNumber, err := net.LookupPort("tcp", targetPort)
	require.NoError(t, err)
	config := map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     listenPort,
			"protocol": "dokodemo-door",
			"settings": map[string]any{"address": targetHost, "port": targetPortNumber, "network": "tcp"},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1",
				"port":    serverPort,
				"users":   []any{map[string]any{"id": xrayRealityPlainUUID, "encryption": "none"}},
			}}},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"show":          true,
					"fingerprint":   "chrome",
					"serverName":    "localhost",
					"publicKey":     base64.RawURLEncoding.EncodeToString(publicKey),
					"shortId":       xrayRealityShortID,
					"mldsa65Verify": base64.RawURLEncoding.EncodeToString(mldsa65Verify),
				},
			},
		}},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	return append(data, '\n')
}

func xrayRealityServerConfig(t *testing.T, port int, originAddr string, privateKey *ecdh.PrivateKey, mldsa65Seed []byte) []byte {
	t.Helper()
	config := map[string]any{
		"log": map[string]any{
			"loglevel": "debug",
		},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "vless",
			"settings": map[string]any{
				"clients": []any{
					map[string]any{"id": xrayRealityPlainUUID},
					map[string]any{"id": xrayRealityVisionUUID, "flow": "xtls-rprx-vision"},
				},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"show":        true,
					"target":      originAddr,
					"serverNames": []string{"localhost"},
					"privateKey":  base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
					"shortIds":    []string{xrayRealityShortID},
					"mldsa65Seed": base64.RawURLEncoding.EncodeToString(mldsa65Seed),
					// Deliberately omit minClientVer. The JSON builder must apply
					// Xray-core's default minimum (currently 26.3.27).
				},
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"tag":      "direct",
			"settings": map[string]any{
				// Current Xray blocks private destinations by default for VLESS.
				// The interop echo server is intentionally loopback-only.
				"finalRules": []any{map[string]any{"action": "allow"}},
			},
		}},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	return append(data, '\n')
}

func padRealityCarrierCertificate(config *tls.Config) {
	certificate := config.Certificates[0]
	leaf := append([]byte(nil), certificate.Certificate[0]...)
	for chainBytes := len(leaf); chainBytes < 6*1024; chainBytes += len(leaf) {
		certificate.Certificate = append(certificate.Certificate, append([]byte(nil), leaf...))
	}
	config.Certificates[0] = certificate
}

func startXrayRealityServer(t *testing.T, xrayBinary string, config []byte, port *vmessInteropReservedTCPPort) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "xray-reality.json")
	require.NoError(t, os.WriteFile(configPath, config, 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, xrayBinary, "run", "-c", configPath)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	port.Release()
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waited := false
	t.Cleanup(func() {
		cancel()
		if !waited {
			<-done
		}
		if t.Failed() {
			t.Log(output.String())
		}
	})

	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port.Port()))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			waited = true
			require.NoError(t, err, output.String())
			t.Fatalf("Xray exited before listening on %s\n%s", address, output.String())
		default:
		}
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Xray did not listen on %s\n%s", address, output.String())
}
