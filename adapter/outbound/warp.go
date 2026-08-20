package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	standardmasque "github.com/metacubex/mihomo/transport/masque"
	"github.com/metacubex/mihomo/transport/tuic/common"
	warpprotocol "github.com/metacubex/mihomo/transport/warp"

	methttp "github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"golang.org/x/crypto/curve25519"
)

const (
	warpModeWireGuard = "wireguard"
	warpModeMASQUE    = "masque"

	warpStateVersion       = 1
	warpDefaultStateDir    = "warp"
	warpDefaultWGPort      = 2408
	warpDefaultMASQUEPort  = 443
	warpDefaultH2Endpoint  = "162.159.198.2"
	warpDefaultAPITimeout  = 30 * time.Second
	warpDefaultTunnelMTU   = 1280
	warpConnectionIDLength = 20
	warpMaxStateSize       = 64 << 10
)

// Warp registers and persists a Cloudflare WARP device on first use, then
// delegates traffic to the existing WireGuard or MASQUE outbound
// implementation. Later starts are built entirely from the persisted state.
type Warp struct {
	*Base
	option WarpOption

	apiClient    *warpprotocol.APIClient
	apiTransport *stdhttp.Transport

	ctx    context.Context
	cancel context.CancelFunc

	initMutex sync.Mutex
	delegate  ProxyAdapter
	closed    bool
}

type WarpOption struct {
	BasicOption
	Name      string `proxy:"name"`
	Mode      string `proxy:"mode"`
	StateDir  string `proxy:"state-dir,omitempty"`
	AcceptTOS bool   `proxy:"accept-tos,omitempty"`

	// Server and Port optionally override the endpoint returned by the device
	// API. Network is used only by MASQUE and accepts h3, h2, or h3-l4proxy.
	Server  string `proxy:"server,omitempty"`
	Port    int    `proxy:"port,omitempty"`
	Network string `proxy:"network,omitempty"`
	SNI     string `proxy:"sni,omitempty"`

	MTU                 int  `proxy:"mtu,omitempty"`
	UDP                 bool `proxy:"udp,omitempty"`
	PersistentKeepalive int  `proxy:"persistent-keepalive,omitempty"`
	Workers             int  `proxy:"workers,omitempty"`
	HandshakeTimeout    int  `proxy:"handshake-timeout,omitempty"`
	SkipCertVerify      bool `proxy:"skip-cert-verify,omitempty"`

	CongestionController string `proxy:"congestion-controller,omitempty"`
	CWND                 int    `proxy:"cwnd,omitempty"`
	BBRProfile           string `proxy:"bbr-profile,omitempty"`

	IPStack IPStackOption `proxy:"ip-stack,omitempty"`

	RemoteDnsResolve bool     `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string `proxy:"dns,omitempty"`
}

type warpRuntime struct {
	apiClient *warpprotocol.APIClient
}

type warpState struct {
	Version     int                  `json:"version"`
	Mode        string               `json:"mode"`
	PrivateKey  string               `json:"private_key"`
	DeviceID    string               `json:"device_id,omitempty"`
	AccessToken string               `json:"access_token,omitempty"`
	Ready       bool                 `json:"ready"`
	Device      *warpprotocol.Device `json:"device,omitempty"`
}

type warpKeyMaterial struct {
	privateKey string
	publicKey  string
	masqueKey  *ecdsa.PrivateKey
}

func NewWarp(option WarpOption) (*Warp, error) {
	return newWarp(option, warpRuntime{})
}

func newWarp(option WarpOption, runtimeConfig warpRuntime) (*Warp, error) {
	option.Mode = strings.ToLower(strings.TrimSpace(option.Mode))
	switch option.Mode {
	case warpModeWireGuard, warpModeMASQUE:
	default:
		return nil, fmt.Errorf("warp mode must be wireguard or masque, got %q", option.Mode)
	}
	if option.Port < 0 || option.Port > 65535 {
		return nil, errors.New("warp port must be 0 or between 1 and 65535")
	}
	if option.HandshakeTimeout < 0 {
		return nil, errors.New("warp handshake timeout must be non-negative")
	}
	if option.MTU < 0 {
		return nil, errors.New("warp MTU must be non-negative")
	}
	option.Network = strings.ToLower(strings.TrimSpace(option.Network))
	if option.Mode == warpModeMASQUE {
		if option.Network == "" {
			option.Network = "h3"
		}
		if option.Network != "h3" && option.Network != "h2" && option.Network != "h3-l4proxy" {
			return nil, fmt.Errorf("warp MASQUE network must be h3, h2, or h3-l4proxy, got %q", option.Network)
		}
	} else if option.Network != "" {
		return nil, errors.New("warp network is only valid in MASQUE mode")
	}
	if option.Network == "h3-l4proxy" {
		option.UDP = false
	}
	option.IPStack.normalize()
	if err := option.IPStack.validate(); err != nil {
		return nil, err
	}

	if option.StateDir == "" {
		option.StateDir = warpDefaultStateDir
	}
	option.StateDir = C.Path.Resolve(option.StateDir)
	if !C.Path.IsSafePath(option.StateDir) {
		return nil, C.Path.ErrNotSafePath(option.StateDir)
	}

	ctx, cancel := context.WithCancel(context.Background())
	outbound := &Warp{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         "api.cloudflareclient.com:443",
			Type:         C.Warp,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: option,
		ctx:    ctx,
		cancel: cancel,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	if runtimeConfig.apiClient != nil {
		outbound.apiClient = runtimeConfig.apiClient
		return outbound, nil
	}
	apiTransport := &stdhttp.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return outbound.dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig: &stdtls.Config{
			RootCAs:    ca.GetCertPool(),
			MinVersion: stdtls.VersionTLS12,
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	outbound.apiTransport = apiTransport
	outbound.apiClient = warpprotocol.NewAPIClient(&stdhttp.Client{
		Transport: apiTransport,
		Timeout:   warpDefaultAPITimeout,
	})
	return outbound, nil
}

func (w *Warp) ensureInitialized(ctx context.Context) (ProxyAdapter, error) {
	w.initMutex.Lock()
	defer w.initMutex.Unlock()
	if w.closed {
		return nil, net.ErrClosed
	}
	if w.delegate != nil {
		return w.delegate, nil
	}

	initCtx, cancel := context.WithCancel(ctx)
	stop := contextutils.AfterFunc(w.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	delegate, err := w.buildDelegate(initCtx)
	if err != nil {
		return nil, err
	}
	w.delegate = delegate
	return delegate, nil
}

func (w *Warp) buildDelegate(ctx context.Context) (ProxyAdapter, error) {
	state, err := w.loadOrCreateState()
	if err != nil {
		return nil, err
	}
	key, err := parseWARPKey(state.PrivateKey, w.option.Mode)
	if err != nil {
		return nil, err
	}
	if !state.Ready {
		state, err = w.initializeState(ctx, state, key)
		if err != nil {
			return nil, err
		}
	}
	peer, err := validateWARPDevice(state.Device)
	if err != nil {
		return nil, err
	}
	if w.option.Mode == warpModeWireGuard {
		return w.buildWireGuard(state.Device, peer, key)
	}
	return w.buildMASQUE(state.Device, peer, key)
}

func parseWARPKey(privateKey, mode string) (*warpKeyMaterial, error) {
	if mode == warpModeWireGuard {
		return parseWireGuardKey(privateKey)
	}
	return parseMASQUEKey(privateKey)
}

func (w *Warp) initializeState(ctx context.Context, state *warpState, key *warpKeyMaterial) (*warpState, error) {
	if state.DeviceID == "" {
		if !w.option.AcceptTOS {
			return nil, errors.New("warp: first-time registration requires accept-tos: true")
		}
		registrationKey := key.publicKey
		if w.option.Mode == warpModeMASQUE {
			var err error
			registrationKey, err = generateWARPRegistrationPublicKey()
			if err != nil {
				return nil, err
			}
		}
		device, err := w.apiClient.RegisterDevice(ctx, registrationKey)
		if err != nil {
			return nil, fmt.Errorf("warp: register device: %w", err)
		}
		if device == nil || device.ID == "" || device.Token == "" {
			return nil, errors.New("warp: registration response is missing device ID or access token")
		}
		state.DeviceID = device.ID
		state.AccessToken = device.Token
		device.Token = ""
		state.Device = device
		state.Ready = false
		if err := writeWarpState(w.statePath(), state); err != nil {
			return nil, err
		}
	}

	keyType := warpprotocol.KeyTypeWireGuard
	if w.option.Mode == warpModeMASQUE {
		keyType = warpprotocol.KeyTypeMASQUE
	}
	device, err := w.apiClient.EnrollDevice(
		ctx,
		state.DeviceID,
		state.AccessToken,
		key.publicKey,
		keyType,
		w.option.Mode,
		w.option.Name,
	)
	if err != nil {
		return nil, fmt.Errorf("warp: enroll %s key: %w", w.option.Mode, err)
	}
	if device == nil || device.ID == "" {
		return nil, errors.New("warp: enrollment response is missing device ID")
	}
	if device.ID != state.DeviceID {
		return nil, fmt.Errorf("warp: enrollment returned device ID %q, expected %q", device.ID, state.DeviceID)
	}
	if _, err := validateWARPDevice(device); err != nil {
		return nil, err
	}
	device.Token = ""
	state.Device = device
	state.Ready = true
	if err := writeWarpState(w.statePath(), state); err != nil {
		return nil, err
	}
	return state, nil
}

func validateWARPDevice(device *warpprotocol.Device) (*warpprotocol.DevicePeer, error) {
	if device == nil {
		return nil, errors.New("warp: device API returned an empty response")
	}
	if len(device.Config.Peers) == 0 {
		return nil, errors.New("warp: device API returned no tunnel peer")
	}
	if device.Config.Interface.Addresses.V4 == "" && device.Config.Interface.Addresses.V6 == "" {
		return nil, errors.New("warp: device API returned no interface address")
	}
	peer := &device.Config.Peers[0]
	if peer.PublicKey == "" {
		return nil, errors.New("warp: device API returned no peer public key")
	}
	return peer, nil
}

func (w *Warp) buildWireGuard(device *warpprotocol.Device, peer *warpprotocol.DevicePeer, key *warpKeyMaterial) (ProxyAdapter, error) {
	server, port, err := warpWireGuardEndpoint(w.option, peer.Endpoint)
	if err != nil {
		return nil, err
	}
	reserved, err := parseWARPClientID(device.Config.ClientID)
	if err != nil {
		return nil, err
	}
	mtu := w.option.MTU
	if mtu == 0 {
		mtu = warpDefaultTunnelMTU
	}
	outbound, err := NewWireGuard(WireGuardOption{
		BasicOption:         w.option.BasicOption,
		Name:                w.option.Name,
		Ip:                  device.Config.Interface.Addresses.V4,
		Ipv6:                device.Config.Interface.Addresses.V6,
		PrivateKey:          key.privateKey,
		MTU:                 mtu,
		UDP:                 w.option.UDP,
		PersistentKeepalive: w.option.PersistentKeepalive,
		Workers:             w.option.Workers,
		IPStack:             w.option.IPStack,
		RemoteDnsResolve:    w.option.RemoteDnsResolve,
		Dns:                 w.option.Dns,
		WireGuardPeerOption: WireGuardPeerOption{
			Server:     server,
			Port:       port,
			PublicKey:  peer.PublicKey,
			Reserved:   reserved,
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("warp: build WireGuard outbound: %w", err)
	}
	outbound.owner = w
	return outbound, nil
}

func (w *Warp) buildMASQUE(device *warpprotocol.Device, peer *warpprotocol.DevicePeer, key *warpKeyMaterial) (ProxyAdapter, error) {
	endpointKey, err := parseWARPPEMPublicKey(peer.PublicKey)
	if err != nil {
		return nil, err
	}
	sni := w.option.SNI
	if sni == "" {
		if w.option.Network == "h3-l4proxy" {
			sni = warpprotocol.L4ConnectSNI
		} else {
			sni = warpprotocol.ConnectSNI
		}
	}
	tlsConfig, err := warpprotocol.PrepareTLSConfig(key.masqueKey, endpointKey, sni, w.option.SkipCertVerify)
	if err != nil {
		return nil, err
	}
	server, port, err := warpMASQUEEndpoint(w.option, peer.Endpoint)
	if err != nil {
		return nil, err
	}
	if w.option.Network == "h3-l4proxy" {
		return newWARPL4(w, server, port, tlsConfig)
	}
	mtu := w.option.MTU
	if mtu == 0 {
		mtu = warpDefaultTunnelMTU
	}
	outbound, err := newMasque(MasqueOption{
		BasicOption:          w.option.BasicOption,
		Name:                 w.option.Name,
		Server:               server,
		Port:                 port,
		Ip:                   device.Config.Interface.Addresses.V4,
		Ipv6:                 device.Config.Interface.Addresses.V6,
		URI:                  warpprotocol.ConnectURI,
		SNI:                  sni,
		MTU:                  mtu,
		UDP:                  w.option.UDP,
		HandshakeTimeout:     w.option.HandshakeTimeout,
		Network:              w.option.Network,
		CongestionController: w.option.CongestionController,
		CWND:                 w.option.CWND,
		BBRProfile:           w.option.BBRProfile,
		IPStack:              w.option.IPStack,
		RemoteDnsResolve:     w.option.RemoteDnsResolve,
		Dns:                  w.option.Dns,
	}, masqueRuntime{
		tlsConfig:              tlsConfig,
		skipRouteAdvertisement: true,
		connectH3: func(ctx context.Context, conn *quic.Conn, uri string) (io.Closer, standardmasque.IpConn, error) {
			return warpprotocol.ConnectTunnel(ctx, conn, uri)
		},
		connectH2: func(ctx context.Context, transport *methttp.Transport, uri string) (io.Closer, standardmasque.IpConn, error) {
			return warpprotocol.ConnectTunnelH2(ctx, transport, uri)
		},
		quicDialOption: common.DialQuicOption{ConnectionIDLength: warpConnectionIDLength},
	})
	if err != nil {
		return nil, fmt.Errorf("warp: build MASQUE outbound: %w", err)
	}
	outbound.owner = w
	return outbound, nil
}

func (w *Warp) loadOrCreateState() (*warpState, error) {
	statePath := w.statePath()
	state, err := readWarpState(statePath, w.option.Mode)
	if err == nil {
		return state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	privateKey, err := generateWARPPrivateKey(w.option.Mode)
	if err != nil {
		return nil, err
	}
	state = &warpState{Version: warpStateVersion, Mode: w.option.Mode, PrivateKey: privateKey}
	if err := createWarpState(statePath, state); errors.Is(err, os.ErrExist) {
		return readWarpState(statePath, w.option.Mode)
	} else if err != nil {
		return nil, err
	}
	return state, nil
}

func (w *Warp) statePath() string {
	identity := strings.Join([]string{w.option.ProviderName, w.option.Name, w.option.Mode}, "\x00")
	filename := utils.MakeHash([]byte(identity)).String() + ".json"
	return filepath.Join(w.option.StateDir, filename)
}

func createWarpState(path string, state *warpState) error {
	data, err := encodeWarpState(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("warp: create state directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("warp: create state: %w", err)
	}
	written := false
	defer func() {
		_ = file.Close()
		if !written {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("warp: write state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("warp: sync state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("warp: close state: %w", err)
	}
	written = true
	return nil
}

func writeWarpState(path string, state *warpState) error {
	data, err := encodeWarpState(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("warp: create state directory: %w", err)
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("warp: create temporary state: %w", err)
	}
	temporaryPath := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("warp: secure temporary state: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("warp: write temporary state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("warp: sync temporary state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("warp: close temporary state: %w", err)
	}
	closed = true
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("warp: replace state: %w", err)
	}
	return nil
}

func encodeWarpState(state *warpState) ([]byte, error) {
	mode := ""
	if state != nil {
		mode = state.Mode
	}
	if err := validateWarpState(state, mode); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("warp: encode state: %w", err)
	}
	return append(data, '\n'), nil
}

func readWarpState(path, mode string) (*warpState, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("warp: read state: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, warpMaxStateSize+1))
	if err != nil {
		return nil, fmt.Errorf("warp: read state: %w", err)
	}
	if len(data) > warpMaxStateSize {
		return nil, errors.New("warp: state exceeds size limit")
	}
	var state warpState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("warp: decode state: %w", err)
	}
	if err := validateWarpState(&state, mode); err != nil {
		return nil, err
	}
	return &state, nil
}

func validateWarpState(state *warpState, mode string) error {
	if state == nil {
		return errors.New("warp: state is empty")
	}
	if state.Version != warpStateVersion {
		return fmt.Errorf("warp: unsupported state version %d", state.Version)
	}
	switch state.Mode {
	case warpModeWireGuard, warpModeMASQUE:
	default:
		return fmt.Errorf("warp: state has invalid mode %q", state.Mode)
	}
	if state.Mode != mode {
		return fmt.Errorf("warp: state mode is %q, expected %q", state.Mode, mode)
	}
	if state.PrivateKey == "" {
		return errors.New("warp: state is missing private key")
	}
	if (state.DeviceID == "") != (state.AccessToken == "") {
		return errors.New("warp: state must contain both device ID and access token")
	}
	if state.Device != nil && state.Device.ID != "" && state.Device.ID != state.DeviceID {
		return fmt.Errorf("warp: state device ID %q does not match registration %q", state.Device.ID, state.DeviceID)
	}
	if !state.Ready {
		return nil
	}
	if state.DeviceID == "" || state.Device == nil {
		return errors.New("warp: ready state is missing registration or device configuration")
	}
	if state.Device.ID != state.DeviceID {
		return fmt.Errorf("warp: state device ID %q does not match registration %q", state.Device.ID, state.DeviceID)
	}
	if _, err := validateWARPDevice(state.Device); err != nil {
		return err
	}
	return nil
}

func generateWARPRegistrationPublicKey() (string, error) {
	publicKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(publicKey); err != nil {
		return "", fmt.Errorf("warp: generate registration public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

func generateWARPPrivateKey(mode string) (string, error) {
	if mode == warpModeWireGuard {
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := rand.Read(privateKey); err != nil {
			return "", fmt.Errorf("warp: generate WireGuard private key: %w", err)
		}
		privateKey[0] &= 248
		privateKey[31] = (privateKey[31] & 127) | 64
		return base64.StdEncoding.EncodeToString(privateKey), nil
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("warp: generate MASQUE private key: %w", err)
	}
	encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("warp: encode MASQUE private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

func parseWireGuardKey(encoded string) (*warpKeyMaterial, error) {
	privateKey, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("warp: decode WireGuard private key: %w", err)
	}
	if len(privateKey) != curve25519.ScalarSize {
		return nil, fmt.Errorf("warp: WireGuard private key must contain %d bytes", curve25519.ScalarSize)
	}
	var private, public [curve25519.ScalarSize]byte
	copy(private[:], privateKey)
	curve25519.ScalarBaseMult(&public, &private)
	return &warpKeyMaterial{
		privateKey: base64.StdEncoding.EncodeToString(private[:]),
		publicKey:  base64.StdEncoding.EncodeToString(public[:]),
	}, nil
}

func parseWARPClientID(encoded string) ([]uint8, error) {
	if encoded == "" {
		return nil, nil
	}
	reserved, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("warp: decode WireGuard client ID: %w", err)
	}
	if len(reserved) != 3 {
		return nil, fmt.Errorf("warp: WireGuard client ID must contain 3 bytes, got %d", len(reserved))
	}
	return reserved, nil
}

func parseMASQUEKey(encoded string) (*warpKeyMaterial, error) {
	privateDER, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		if block, _ := pem.Decode([]byte(encoded)); block != nil {
			privateDER = block.Bytes
		} else {
			return nil, fmt.Errorf("warp: decode MASQUE private key: %w", err)
		}
	}
	privateKey, err := x509.ParseECPrivateKey(privateDER)
	if err != nil {
		return nil, fmt.Errorf("warp: parse MASQUE private key: %w", err)
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, errors.New("warp: MASQUE private key must use P-256")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("warp: encode MASQUE public key: %w", err)
	}
	canonicalPrivateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("warp: encode MASQUE private key: %w", err)
	}
	return &warpKeyMaterial{
		privateKey: base64.StdEncoding.EncodeToString(canonicalPrivateDER),
		publicKey:  base64.StdEncoding.EncodeToString(publicDER),
		masqueKey:  privateKey,
	}, nil
}

func parseWARPPEMPublicKey(encoded string) (*ecdsa.PublicKey, error) {
	var publicDER []byte
	if block, _ := pem.Decode([]byte(encoded)); block != nil {
		publicDER = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("warp: decode MASQUE endpoint public key: expected PEM or Base64 DER")
		}
		publicDER = decoded
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return nil, fmt.Errorf("warp: parse MASQUE endpoint public key: %w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("warp: MASQUE endpoint public key must be P-256 ECDSA")
	}
	return publicKey, nil
}

func warpWireGuardEndpoint(option WarpOption, endpoint warpprotocol.DeviceEndpoint) (string, int, error) {
	rawEndpoint := option.Server
	if rawEndpoint == "" {
		rawEndpoint = endpoint.Host
		if rawEndpoint == "" {
			rawEndpoint = preferredWARPEndpoint(option.IPVersion, endpoint.V4, endpoint.V6)
		}
	}
	server, embeddedPort, err := splitWARPEndpoint(rawEndpoint)
	if err != nil {
		return "", 0, fmt.Errorf("warp: WireGuard endpoint: %w", err)
	}
	port := option.Port
	if port == 0 {
		port = embeddedPort
	}
	if port == 0 {
		port = warpDefaultWGPort
	}
	return server, port, nil
}

func warpMASQUEEndpoint(option WarpOption, endpoint warpprotocol.DeviceEndpoint) (string, int, error) {
	rawEndpoint := option.Server
	if rawEndpoint == "" {
		if option.Network == "h2" {
			if option.IPVersion == C.IPv6Only {
				return "", 0, errors.New("warp: network h2 with IPv6 requires an explicit server")
			}
			rawEndpoint = warpDefaultH2Endpoint
		} else {
			rawEndpoint = preferredWARPEndpoint(option.IPVersion, endpoint.V4, endpoint.V6)
		}
	}
	server, embeddedPort, err := splitWARPEndpoint(rawEndpoint)
	if err != nil {
		return "", 0, fmt.Errorf("warp: MASQUE endpoint: %w", err)
	}
	port := option.Port
	if port == 0 {
		port = embeddedPort
	}
	if port == 0 {
		port = warpDefaultMASQUEPort
	}
	return server, port, nil
}

func preferredWARPEndpoint(prefer C.DNSPrefer, ipv4, ipv6 string) string {
	switch prefer {
	case C.IPv4Only:
		return ipv4
	case C.IPv6Only:
		return ipv6
	case C.IPv6Prefer:
		if ipv6 != "" {
			return ipv6
		}
		return ipv4
	default:
		if ipv4 != "" {
			return ipv4
		}
		return ipv6
	}
}

func splitWARPEndpoint(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, errors.New("missing endpoint")
	}
	if address, err := netip.ParseAddrPort(raw); err == nil {
		return address.Addr().String(), int(address.Port()), nil
	}
	if host, portText, err := net.SplitHostPort(raw); err == nil {
		if host == "" {
			return "", 0, errors.New("missing host")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 0 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port %q", portText)
		}
		return host, port, nil
	}
	if address, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return address.String(), 0, nil
	}
	if strings.ContainsAny(raw, " \t\r\n[]:/?#") {
		return "", 0, fmt.Errorf("invalid host %q", raw)
	}
	return raw, 0, nil
}

func (w *Warp) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	delegate, err := w.ensureInitialized(ctx)
	if err != nil {
		return nil, err
	}
	return delegate.DialContext(ctx, metadata)
}

func (w *Warp) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	delegate, err := w.ensureInitialized(ctx)
	if err != nil {
		return nil, err
	}
	return delegate.ListenPacketContext(ctx, metadata)
}

func (w *Warp) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	delegate, err := w.ensureInitialized(ctx)
	if err != nil {
		return err
	}
	return delegate.ResolveUDP(ctx, metadata)
}

func (w *Warp) ProxyInfo() C.ProxyInfo {
	info := w.Base.ProxyInfo()
	info.DialerProxy = w.option.DialerProxy
	return info
}

func (w *Warp) Addr() string {
	w.initMutex.Lock()
	defer w.initMutex.Unlock()
	if w.delegate != nil {
		return w.delegate.Addr()
	}
	return w.Base.Addr()
}

func (w *Warp) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (w *Warp) Close() error {
	w.cancel()
	w.initMutex.Lock()
	if w.closed {
		w.initMutex.Unlock()
		return nil
	}
	w.closed = true
	delegate := w.delegate
	w.delegate = nil
	w.initMutex.Unlock()
	if w.apiTransport != nil {
		w.apiTransport.CloseIdleConnections()
	}
	if delegate != nil {
		return delegate.Close()
	}
	return nil
}
