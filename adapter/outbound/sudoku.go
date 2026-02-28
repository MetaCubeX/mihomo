package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/sudoku"
	"github.com/metacubex/mihomo/transport/sudoku/obfs/httpmask"
)

type Sudoku struct {
	*Base
	option   *SudokuOption
	baseConf sudoku.ProtocolConfig

	muxMu     sync.Mutex
	muxClient *sudoku.MultiplexClient

	httpMaskMu     sync.Mutex
	httpMaskClient *httpmask.TunnelClient
	httpMaskKey    string
}

type SudokuOption struct {
	BasicOption
	Name               string                 `proxy:"name"`
	Server             string                 `proxy:"server"`
	Port               int                    `proxy:"port"`
	Key                string                 `proxy:"key"`
	AEADMethod         string                 `proxy:"aead-method,omitempty"`
	PaddingMin         *int                   `proxy:"padding-min,omitempty"`
	PaddingMax         *int                   `proxy:"padding-max,omitempty"`
	TableType          string                 `proxy:"table-type,omitempty"` // "prefer_ascii" or "prefer_entropy"
	EnablePureDownlink *bool                  `proxy:"enable-pure-downlink,omitempty"`
	HTTPMask           *bool                  `proxy:"http-mask,omitempty"`
	HTTPMaskMode       string                 `proxy:"http-mask-mode,omitempty"`      // "legacy" (default), "stream", "poll", "auto", "ws"
	HTTPMaskTLS        bool                   `proxy:"http-mask-tls,omitempty"`       // only for http-mask-mode stream/poll/auto
	HTTPMaskHost       string                 `proxy:"http-mask-host,omitempty"`      // optional Host/SNI override (domain or domain:port)
	PathRoot           string                 `proxy:"path-root,omitempty"`           // optional first-level path prefix for HTTP tunnel endpoints
	HTTPMaskMultiplex  string                 `proxy:"http-mask-multiplex,omitempty"` // "off" (default), "auto" (reuse h1/h2), "on" (single tunnel, multi-target)
	HTTPMaskOptions    *SudokuHTTPMaskOptions `proxy:"httpmask,omitempty"`
	CustomTable        string                 `proxy:"custom-table,omitempty"`  // optional custom byte layout, e.g. xpxvvpvv
	CustomTables       []string               `proxy:"custom-tables,omitempty"` // optional table rotation patterns, overrides custom-table when non-empty
}

type SudokuHTTPMaskOptions struct {
	Disable   bool   `proxy:"disable,omitempty"`
	Mode      string `proxy:"mode,omitempty"`
	TLS       bool   `proxy:"tls,omitempty"`
	Host      string `proxy:"host,omitempty"`
	PathRoot  string `proxy:"path_root,omitempty"`
	Multiplex string `proxy:"multiplex,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (s *Sudoku) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	cfg, err := s.buildConfig(metadata)
	if err != nil {
		return nil, err
	}

	muxMode := normalizeHTTPMaskMultiplex(cfg.HTTPMaskMultiplex)
	if muxMode == "on" && !cfg.DisableHTTPMask && httpTunnelModeEnabled(cfg.HTTPMaskMode) {
		stream, muxErr := s.dialMultiplex(ctx, cfg.TargetAddress)
		if muxErr == nil {
			return NewConn(stream, s), nil
		}
		return nil, muxErr
	}

	c, err := s.dialAndHandshake(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() { safeConnClose(c, err) }()

	addrBuf, err := sudoku.EncodeAddress(cfg.TargetAddress)
	if err != nil {
		return nil, fmt.Errorf("encode target address failed: %w", err)
	}

	if err = sudoku.WriteKIPMessage(c, sudoku.KIPTypeOpenTCP, addrBuf); err != nil {
		return nil, fmt.Errorf("send target address failed: %w", err)
	}

	return NewConn(c, s), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Sudoku) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := s.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	cfg, err := s.buildConfig(metadata)
	if err != nil {
		return nil, err
	}

	c, err := s.dialAndHandshake(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if err = sudoku.WriteKIPMessage(c, sudoku.KIPTypeStartUoT, nil); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("start uot failed: %w", err)
	}

	return newPacketConn(N.NewThreadSafePacketConn(sudoku.NewUoTPacketConn(c)), s), nil
}

// SupportUOT implements C.ProxyAdapter
func (s *Sudoku) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (s *Sudoku) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func (s *Sudoku) buildConfig(metadata *C.Metadata) (*sudoku.ProtocolConfig, error) {
	if metadata == nil || metadata.DstPort == 0 || !metadata.Valid() {
		return nil, fmt.Errorf("invalid metadata for sudoku outbound")
	}

	cfg := s.baseConf
	cfg.TargetAddress = metadata.RemoteAddress()

	if err := cfg.ValidateClient(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func NewSudoku(option SudokuOption) (*Sudoku, error) {
	if option.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if option.Port <= 0 || option.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", option.Port)
	}
	if option.Key == "" {
		return nil, fmt.Errorf("key is required")
	}

	defaultConf := sudoku.DefaultConfig()
	tableType, err := sudoku.NormalizeTableType(option.TableType)
	if err != nil {
		return nil, err
	}
	paddingMin, paddingMax := sudoku.ResolvePadding(option.PaddingMin, option.PaddingMax, defaultConf.PaddingMin, defaultConf.PaddingMax)
	enablePureDownlink := sudoku.DerefBool(option.EnablePureDownlink, defaultConf.EnablePureDownlink)

	disableHTTPMask := defaultConf.DisableHTTPMask
	if option.HTTPMask != nil {
		disableHTTPMask = !*option.HTTPMask
	}
	httpMaskMode := defaultConf.HTTPMaskMode
	if option.HTTPMaskMode != "" {
		httpMaskMode = option.HTTPMaskMode
	}
	httpMaskTLS := option.HTTPMaskTLS
	httpMaskHost := option.HTTPMaskHost
	pathRoot := strings.TrimSpace(option.PathRoot)
	httpMaskMultiplex := defaultConf.HTTPMaskMultiplex
	if option.HTTPMaskMultiplex != "" {
		httpMaskMultiplex = option.HTTPMaskMultiplex
	}

	if hm := option.HTTPMaskOptions; hm != nil {
		disableHTTPMask = hm.Disable
		if hm.Mode != "" {
			httpMaskMode = hm.Mode
		}
		httpMaskTLS = hm.TLS
		httpMaskHost = hm.Host
		if pr := strings.TrimSpace(hm.PathRoot); pr != "" {
			pathRoot = pr
		}
		if mux := strings.TrimSpace(hm.Multiplex); mux != "" {
			httpMaskMultiplex = mux
		} else {
			httpMaskMultiplex = defaultConf.HTTPMaskMultiplex
		}
	}

	baseConf := sudoku.ProtocolConfig{
		ServerAddress:           net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
		Key:                     option.Key,
		AEADMethod:              defaultConf.AEADMethod,
		PaddingMin:              paddingMin,
		PaddingMax:              paddingMax,
		EnablePureDownlink:      enablePureDownlink,
		HandshakeTimeoutSeconds: defaultConf.HandshakeTimeoutSeconds,
		DisableHTTPMask:         disableHTTPMask,
		HTTPMaskMode:            httpMaskMode,
		HTTPMaskTLSEnabled:      httpMaskTLS,
		HTTPMaskHost:            httpMaskHost,
		HTTPMaskPathRoot:        pathRoot,
		HTTPMaskMultiplex:       httpMaskMultiplex,
	}
	tables, err := sudoku.NewClientTablesWithCustomPatterns(sudoku.ClientAEADSeed(option.Key), tableType, option.CustomTable, option.CustomTables)
	if err != nil {
		return nil, fmt.Errorf("build table(s) failed: %w", err)
	}
	if len(tables) == 1 {
		baseConf.Table = tables[0]
	} else {
		baseConf.Tables = tables
	}
	if option.AEADMethod != "" {
		baseConf.AEADMethod = option.AEADMethod
	}

	outbound := &Sudoku{
		Base: &Base{
			name:   option.Name,
			addr:   baseConf.ServerAddress,
			tp:     C.Sudoku,
			pdName: option.ProviderName,
			udp:    true,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		option:   &option,
		baseConf: baseConf,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

func (s *Sudoku) Close() error {
	s.resetMuxClient()
	s.resetHTTPMaskClient()
	return s.Base.Close()
}

func normalizeHTTPMaskMultiplex(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "off":
		return "off"
	case "auto":
		return "auto"
	case "on":
		return "on"
	default:
		return "off"
	}
}

func httpTunnelModeEnabled(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "stream", "poll", "auto", "ws":
		return true
	default:
		return false
	}
}

func (s *Sudoku) dialAndHandshake(ctx context.Context, cfg *sudoku.ProtocolConfig) (_ net.Conn, err error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	handshakeCfg := *cfg
	if !handshakeCfg.DisableHTTPMask && httpTunnelModeEnabled(handshakeCfg.HTTPMaskMode) {
		handshakeCfg.DisableHTTPMask = true
	}

	upgrade := func(raw net.Conn) (net.Conn, error) {
		return sudoku.ClientHandshake(raw, &handshakeCfg)
	}

	var (
		c             net.Conn
		handshakeDone bool
	)
	if !cfg.DisableHTTPMask && httpTunnelModeEnabled(cfg.HTTPMaskMode) {
		muxMode := normalizeHTTPMaskMultiplex(cfg.HTTPMaskMultiplex)
		if muxMode == "auto" && strings.ToLower(strings.TrimSpace(cfg.HTTPMaskMode)) != "ws" {
			if client, cerr := s.getOrCreateHTTPMaskClient(cfg); cerr == nil && client != nil {
				c, err = client.DialTunnel(ctx, httpmask.TunnelDialOptions{
					Mode:         cfg.HTTPMaskMode,
					TLSEnabled:   cfg.HTTPMaskTLSEnabled,
					HostOverride: cfg.HTTPMaskHost,
					PathRoot:     cfg.HTTPMaskPathRoot,
					AuthKey:      sudoku.ClientAEADSeed(cfg.Key),
					Upgrade:      upgrade,
					Multiplex:    cfg.HTTPMaskMultiplex,
					DialContext:  s.dialer.DialContext,
				})
				if err != nil {
					s.resetHTTPMaskClient()
				}
			}
		}
		if c == nil && err == nil {
			c, err = sudoku.DialHTTPMaskTunnel(ctx, cfg.ServerAddress, cfg, s.dialer.DialContext, upgrade)
		}
		if err == nil && c != nil {
			handshakeDone = true
		}
	}
	if c == nil && err == nil {
		c, err = s.dialer.DialContext(ctx, "tcp", s.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}

	defer func() { safeConnClose(c, err) }()

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	if !handshakeDone {
		c, err = sudoku.ClientHandshake(c, &handshakeCfg)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (s *Sudoku) dialMultiplex(ctx context.Context, targetAddress string) (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		client, err := s.getOrCreateMuxClient(ctx)
		if err != nil {
			return nil, err
		}

		stream, err := client.Dial(ctx, targetAddress)
		if err != nil {
			s.resetMuxClient()
			continue
		}

		return stream, nil
	}
	return nil, fmt.Errorf("multiplex open stream failed")
}

func (s *Sudoku) getOrCreateMuxClient(ctx context.Context) (*sudoku.MultiplexClient, error) {
	if s == nil {
		return nil, fmt.Errorf("nil adapter")
	}

	s.muxMu.Lock()
	if s.muxClient != nil && !s.muxClient.IsClosed() {
		client := s.muxClient
		s.muxMu.Unlock()
		return client, nil
	}
	s.muxMu.Unlock()

	s.muxMu.Lock()
	defer s.muxMu.Unlock()

	if s.muxClient != nil && !s.muxClient.IsClosed() {
		return s.muxClient, nil
	}

	baseCfg := s.baseConf
	baseConn, err := s.dialAndHandshake(ctx, &baseCfg)
	if err != nil {
		return nil, err
	}

	client, err := sudoku.StartMultiplexClient(baseConn)
	if err != nil {
		_ = baseConn.Close()
		return nil, err
	}

	s.muxClient = client
	return client, nil
}

func (s *Sudoku) resetMuxClient() {
	s.muxMu.Lock()
	defer s.muxMu.Unlock()
	if s.muxClient != nil {
		_ = s.muxClient.Close()
		s.muxClient = nil
	}
}

func (s *Sudoku) resetHTTPMaskClient() {
	s.httpMaskMu.Lock()
	defer s.httpMaskMu.Unlock()
	if s.httpMaskClient != nil {
		s.httpMaskClient.CloseIdleConnections()
		s.httpMaskClient = nil
		s.httpMaskKey = ""
	}
}

func (s *Sudoku) getOrCreateHTTPMaskClient(cfg *sudoku.ProtocolConfig) (*httpmask.TunnelClient, error) {
	if s == nil || cfg == nil {
		return nil, fmt.Errorf("nil adapter or config")
	}

	key := cfg.ServerAddress + "|" + strconv.FormatBool(cfg.HTTPMaskTLSEnabled) + "|" + strings.TrimSpace(cfg.HTTPMaskHost)

	s.httpMaskMu.Lock()
	if s.httpMaskClient != nil && s.httpMaskKey == key {
		client := s.httpMaskClient
		s.httpMaskMu.Unlock()
		return client, nil
	}
	s.httpMaskMu.Unlock()

	client, err := httpmask.NewTunnelClient(cfg.ServerAddress, httpmask.TunnelClientOptions{
		TLSEnabled:   cfg.HTTPMaskTLSEnabled,
		HostOverride: cfg.HTTPMaskHost,
		DialContext:  s.dialer.DialContext,
		MaxIdleConns: 32,
	})
	if err != nil {
		return nil, err
	}

	s.httpMaskMu.Lock()
	defer s.httpMaskMu.Unlock()
	if s.httpMaskClient != nil && s.httpMaskKey == key {
		client.CloseIdleConnections()
		return s.httpMaskClient, nil
	}
	if s.httpMaskClient != nil {
		s.httpMaskClient.CloseIdleConnections()
	}
	s.httpMaskClient = client
	s.httpMaskKey = key
	return client, nil
}
