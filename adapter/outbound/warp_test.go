package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	warpprotocol "github.com/metacubex/mihomo/transport/warp"
	"github.com/stretchr/testify/require"
)

func TestWARPKeyGeneration(t *testing.T) {
	for _, mode := range []string{warpModeWireGuard, warpModeMASQUE} {
		t.Run(mode, func(t *testing.T) {
			encoded, err := generateWARPPrivateKey(mode)
			require.NoError(t, err)
			if mode == warpModeWireGuard {
				material, err := parseWireGuardKey(encoded)
				require.NoError(t, err)
				require.NotEmpty(t, material.publicKey)
				require.Nil(t, material.masqueKey)
				return
			}
			material, err := parseMASQUEKey(encoded)
			require.NoError(t, err)
			require.NotEmpty(t, material.publicKey)
			require.NotNil(t, material.masqueKey)
			require.Equal(t, elliptic.P256(), material.masqueKey.Curve)
		})
	}
}

func TestWARPInitialStateKeepsAStablePrivateKey(t *testing.T) {
	w := &Warp{option: WarpOption{
		Name:     "warp-test",
		Mode:     warpModeMASQUE,
		StateDir: t.TempDir(),
	}}
	first, err := w.loadOrCreateState()
	require.NoError(t, err)
	second, err := w.loadOrCreateState()
	require.NoError(t, err)
	require.Equal(t, first.PrivateKey, second.PrivateKey)
	require.False(t, first.Ready)

	data, err := os.ReadFile(w.statePath())
	require.NoError(t, err)
	require.Contains(t, string(data), first.PrivateKey)
	require.NotContains(t, string(data), "access_token")
}

func TestNewWARPAutoRegistersWithoutConfiguredCredentials(t *testing.T) {
	w, err := NewWarp(WarpOption{Name: "warp-test", Mode: "MASQUE"})
	require.NoError(t, err)
	defer w.Close()
	require.Equal(t, C.Warp, w.Type())
	require.Equal(t, warpModeMASQUE, w.option.Mode)
	require.Equal(t, "h3", w.option.Network)
	require.NotEmpty(t, w.option.StateDir)
}

func TestWARPRequiresExplicitTOSAcceptanceOnlyForRegistration(t *testing.T) {
	stateDir := useTemporaryWARPHome(t)
	peerPrivateKey, err := generateWARPPrivateKey(warpModeWireGuard)
	require.NoError(t, err)
	peerMaterial, err := parseWireGuardKey(peerPrivateKey)
	require.NoError(t, err)
	api, calls := testWARPAPI(t, warpModeWireGuard, peerMaterial.publicKey, warpprotocol.DeviceEndpoint{Host: "engage.example:2408"})
	w, err := newWarp(WarpOption{Name: "warp-tos", Mode: warpModeWireGuard, StateDir: stateDir}, warpRuntime{apiClient: api})
	require.NoError(t, err)
	defer w.Close()

	_, err = w.buildDelegate(context.Background())
	require.ErrorContains(t, err, "accept-tos: true")
	require.Empty(t, calls.requestMethods())
}

func TestWARPDerivesWireGuardOutboundAndReusesCompleteState(t *testing.T) {
	stateDir := useTemporaryWARPHome(t)
	peerPrivateKey, err := generateWARPPrivateKey(warpModeWireGuard)
	require.NoError(t, err)
	peerMaterial, err := parseWireGuardKey(peerPrivateKey)
	require.NoError(t, err)

	api, calls := testWARPAPI(t, warpModeWireGuard, peerMaterial.publicKey, warpprotocol.DeviceEndpoint{Host: "engage.example:2408"})
	option := WarpOption{Name: "warp-wg", Mode: warpModeWireGuard, StateDir: stateDir, AcceptTOS: true, UDP: true}
	w, err := newWarp(option, warpRuntime{apiClient: api})
	require.NoError(t, err)
	defer w.Close()

	delegate, err := w.buildDelegate(context.Background())
	require.NoError(t, err)
	defer delegate.Close()
	wg, ok := delegate.(*WireGuard)
	require.True(t, ok)
	require.Same(t, w, wg.owner)
	require.Equal(t, "engage.example:2408", wg.Addr())
	require.Equal(t, []string{http.MethodPost, http.MethodPatch}, calls.requestMethods())
	registrationKey, enrolledKey := calls.keys()
	require.Equal(t, registrationKey, enrolledKey, "WireGuard must enroll the same key that was registered")

	state, err := readWarpState(w.statePath(), warpModeWireGuard)
	require.NoError(t, err)
	require.True(t, state.Ready)
	require.Equal(t, "device-id", state.DeviceID)
	require.Equal(t, "access-token", state.AccessToken)
	require.NotEmpty(t, state.PrivateKey)
	require.Equal(t, "172.16.0.2", state.Device.Config.Interface.Addresses.V4)
	rawState, err := os.ReadFile(w.statePath())
	require.NoError(t, err)
	require.Contains(t, string(rawState), "access-token")
	require.Contains(t, string(rawState), peerMaterial.publicKey)

	reloaded, err := newWarp(option, warpRuntime{apiClient: api})
	require.NoError(t, err)
	defer reloaded.Close()
	reloadedDelegate, err := reloaded.buildDelegate(context.Background())
	require.NoError(t, err)
	defer reloadedDelegate.Close()
	require.Equal(t, []string{http.MethodPost, http.MethodPatch}, calls.requestMethods(), "a complete state must not call the registration API again")
}

func TestWARPDerivesMASQUEOutboundAfterRegistrationAndEnroll(t *testing.T) {
	stateDir := useTemporaryWARPHome(t)
	peerPEM := testWARPMASQUEPeerKey(t)
	api, calls := testWARPAPI(t, warpModeMASQUE, peerPEM, warpprotocol.DeviceEndpoint{V4: "192.0.2.10:0"})
	w, err := newWarp(WarpOption{
		Name:      "warp-masque",
		Mode:      warpModeMASQUE,
		StateDir:  stateDir,
		AcceptTOS: true,
		Network:   "h3",
		UDP:       true,
	}, warpRuntime{apiClient: api})
	require.NoError(t, err)
	defer w.Close()

	delegate, err := w.buildDelegate(context.Background())
	require.NoError(t, err)
	defer delegate.Close()
	masque, ok := delegate.(*Masque)
	require.True(t, ok)
	require.Same(t, w, masque.owner)
	require.Equal(t, "192.0.2.10:443", masque.Addr())
	require.Equal(t, warpprotocol.ConnectURI, masque.uri)
	require.Equal(t, warpConnectionIDLength, masque.quicDialOpt.ConnectionIDLength)
	require.Equal(t, []string{http.MethodPost, http.MethodPatch}, calls.requestMethods())
	registrationKey, enrolledKey := calls.keys()
	require.NotEqual(t, registrationKey, enrolledKey, "MASQUE registration must use the disposable WireGuard key described by usque")

	state, err := readWarpState(w.statePath(), warpModeMASQUE)
	require.NoError(t, err)
	require.True(t, state.Ready)
	material, err := parseMASQUEKey(state.PrivateKey)
	require.NoError(t, err)
	require.Equal(t, material.publicKey, enrolledKey)
	require.Equal(t, peerPEM, state.Device.Config.Peers[0].PublicKey)
}

func TestWARPResumesAnIncompleteRegistration(t *testing.T) {
	stateDir := useTemporaryWARPHome(t)
	peerPEM := testWARPMASQUEPeerKey(t)
	api, calls := testWARPAPI(t, warpModeMASQUE, peerPEM, warpprotocol.DeviceEndpoint{V4: "192.0.2.15:0"})
	option := WarpOption{Name: "warp-resume", Mode: warpModeMASQUE, StateDir: stateDir, Network: "h3", UDP: true}
	w, err := newWarp(option, warpRuntime{apiClient: api})
	require.NoError(t, err)
	defer w.Close()
	privateKey, err := generateWARPPrivateKey(warpModeMASQUE)
	require.NoError(t, err)
	require.NoError(t, createWarpState(w.statePath(), &warpState{
		Version:     warpStateVersion,
		Mode:        warpModeMASQUE,
		PrivateKey:  privateKey,
		DeviceID:    "device-id",
		AccessToken: "access-token",
	}))

	delegate, err := w.buildDelegate(context.Background())
	require.NoError(t, err)
	defer delegate.Close()
	require.Equal(t, []string{http.MethodPatch}, calls.requestMethods())
	state, err := readWarpState(w.statePath(), warpModeMASQUE)
	require.NoError(t, err)
	require.True(t, state.Ready)
}

func TestWARPDerivesLegacyL4ProxyWithoutExposingItAsStandardMASQUE(t *testing.T) {
	stateDir := useTemporaryWARPHome(t)
	peerPEM := testWARPMASQUEPeerKey(t)
	api, _ := testWARPAPI(t, warpModeMASQUE, peerPEM, warpprotocol.DeviceEndpoint{V4: "192.0.2.20:0"})
	w, err := newWarp(WarpOption{
		Name:      "warp-l4",
		Mode:      warpModeMASQUE,
		StateDir:  stateDir,
		AcceptTOS: true,
		Network:   "h3-l4proxy",
		UDP:       true,
	}, warpRuntime{apiClient: api})
	require.NoError(t, err)
	defer w.Close()
	require.False(t, w.SupportUDP())

	delegate, err := w.buildDelegate(context.Background())
	require.NoError(t, err)
	defer delegate.Close()
	l4, ok := delegate.(*warpL4)
	require.True(t, ok)
	require.Same(t, w, l4.owner)
	require.Equal(t, "192.0.2.20:443", l4.Addr())
	require.Equal(t, warpprotocol.L4ConnectSNI, l4.tlsConfig.ServerName)
}

func TestWARPEndpointSelection(t *testing.T) {
	server, port, err := warpMASQUEEndpoint(WarpOption{Network: "h3", Server: "proxy.example:8443"}, warpprotocol.DeviceEndpoint{})
	require.NoError(t, err)
	require.Equal(t, "proxy.example", server)
	require.Equal(t, 8443, port)

	server, port, err = warpMASQUEEndpoint(WarpOption{Network: "h2"}, warpprotocol.DeviceEndpoint{})
	require.NoError(t, err)
	require.Equal(t, warpDefaultH2Endpoint, server)
	require.Equal(t, warpDefaultMASQUEPort, port)

	server, port, err = warpMASQUEEndpoint(WarpOption{Network: "h3", BasicOption: BasicOption{IPVersion: C.IPv6Prefer}}, warpprotocol.DeviceEndpoint{
		V4: "192.0.2.1:0",
		V6: "[2001:db8::1]:0",
	})
	require.NoError(t, err)
	require.Equal(t, "2001:db8::1", server)
	require.Equal(t, warpDefaultMASQUEPort, port)

	_, _, err = warpMASQUEEndpoint(WarpOption{Network: "h3", Server: "proxy.example:not-a-port"}, warpprotocol.DeviceEndpoint{})
	require.ErrorContains(t, err, "invalid port")

	_, _, err = warpMASQUEEndpoint(WarpOption{Network: "h3", Server: ":443"}, warpprotocol.DeviceEndpoint{})
	require.ErrorContains(t, err, "missing host")
}

func TestParseWARPPrivateKeyRejectsWrongFormats(t *testing.T) {
	_, err := parseWireGuardKey(base64.StdEncoding.EncodeToString([]byte("short")))
	require.ErrorContains(t, err, "32 bytes")
	_, err = parseMASQUEKey(base64.StdEncoding.EncodeToString([]byte("not DER")))
	require.ErrorContains(t, err, "parse MASQUE private key")
	_, err = parseWARPPEMPublicKey(strings.Repeat("x", 10))
	require.ErrorContains(t, err, "endpoint public key")
}

func TestParseWARPClientID(t *testing.T) {
	reserved, err := parseWARPClientID(base64.StdEncoding.EncodeToString([]byte{1, 2, 3}))
	require.NoError(t, err)
	require.Equal(t, []uint8{1, 2, 3}, reserved)

	_, err = parseWARPClientID("not-base64")
	require.ErrorContains(t, err, "decode WireGuard client ID")
	_, err = parseWARPClientID(base64.StdEncoding.EncodeToString([]byte{1, 2}))
	require.ErrorContains(t, err, "must contain 3 bytes")
}

type warpAPICalls struct {
	mutex           sync.Mutex
	methods         []string
	registrationKey string
	enrolledKey     string
}

func (c *warpAPICalls) record(method, key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.methods = append(c.methods, method)
	if method == http.MethodPost {
		c.registrationKey = key
	} else if method == http.MethodPatch {
		c.enrolledKey = key
	}
}

func (c *warpAPICalls) requestMethods() []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]string(nil), c.methods...)
}

func (c *warpAPICalls) keys() (string, string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.registrationKey, c.enrolledKey
}

func testWARPAPI(t *testing.T, mode, peerPublicKey string, endpoint warpprotocol.DeviceEndpoint) (*warpprotocol.APIClient, *warpAPICalls) {
	t.Helper()
	calls := &warpAPICalls{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var keyType, tunnelType, key string
		switch r.Method {
		case http.MethodPost:
			require.Equal(t, "/test/reg", r.URL.Path)
			require.Empty(t, r.Header.Get("Authorization"))
			var registration warpprotocol.Registration
			require.NoError(t, json.NewDecoder(r.Body).Decode(&registration))
			require.Equal(t, warpprotocol.KeyTypeWireGuard, registration.KeyType)
			require.Equal(t, warpprotocol.TunnelWireGuard, registration.TunnelType)
			keyType, tunnelType, key = registration.KeyType, registration.TunnelType, registration.Key
		case http.MethodPatch:
			require.Equal(t, "/test/reg/device-id", r.URL.Path)
			require.Equal(t, "Bearer access-token", r.Header.Get("Authorization"))
			var update warpprotocol.DeviceUpdate
			require.NoError(t, json.NewDecoder(r.Body).Decode(&update))
			require.Equal(t, mode, update.TunnelType)
			require.NotEmpty(t, update.Name)
			keyType, tunnelType, key = update.KeyType, update.TunnelType, update.Key
		default:
			t.Errorf("unexpected WARP API method %s", r.Method)
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		decodedKey, err := base64.StdEncoding.DecodeString(key)
		require.NoError(t, err)
		require.NotEmpty(t, decodedKey)
		calls.record(r.Method, key)
		response := warpprotocol.Device{
			ID:         "device-id",
			KeyType:    keyType,
			TunnelType: tunnelType,
			Config: warpprotocol.DeviceConfig{
				ClientID: base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
				Interface: warpprotocol.DeviceInterface{Addresses: warpprotocol.DeviceAddresses{
					V4: "172.16.0.2",
					V6: "2606:4700:110:8f00::2",
				}},
				Peers: []warpprotocol.DevicePeer{{PublicKey: peerPublicKey, Endpoint: endpoint}},
			},
		}
		if r.Method == http.MethodPost {
			response.Token = "access-token"
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	t.Cleanup(server.Close)
	client := warpprotocol.NewAPIClient(server.Client())
	client.BaseURL = server.URL
	client.APIVersion = "test"
	return client, calls
}

func testWARPMASQUEPeerKey(t *testing.T) string {
	t.Helper()
	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerDER, err := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: peerDER}))
}

func useTemporaryWARPHome(t *testing.T) string {
	t.Helper()
	originalHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(originalHome) })
	return "warp-state"
}
