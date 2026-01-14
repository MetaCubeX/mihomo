package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/sudoku"
)

type Sudoku struct {
	*Base
	option   *SudokuOption
	baseConf sudoku.ProtocolConfig

	httpMaskMu     sync.Mutex
	httpMaskClient *sudoku.HTTPMaskTunnelClient

	muxMu           sync.Mutex
	muxClient       *sudoku.MultiplexClient
	muxBackoffUntil time.Time
	muxLastErr      error
}

type SudokuOption struct {
	BasicOption
	Name               string   `proxy:"name"`
	Server             string   `proxy:"server"`
	Port               int      `proxy:"port"`
	Key                string   `proxy:"key"`
	AEADMethod         string   `proxy:"aead-method,omitempty"`
	PaddingMin         *int     `proxy:"padding-min,omitempty"`
	PaddingMax         *int     `proxy:"padding-max,omitempty"`
	TableType          string   `proxy:"table-type,omitempty"` // "prefer_ascii" or "prefer_entropy"
	EnablePureDownlink *bool    `proxy:"enable-pure-downlink,omitempty"`
	HTTPMask           bool     `proxy:"http-mask,omitempty"`
	HTTPMaskMode       string   `proxy:"http-mask-mode,omitempty"`      // "legacy" (default), "stream", "poll", "auto"
	HTTPMaskTLS        bool     `proxy:"http-mask-tls,omitempty"`       // only for http-mask-mode stream/poll/auto
	HTTPMaskHost       string   `proxy:"http-mask-host,omitempty"`      // optional Host/SNI override (domain or domain:port)
	PathRoot           string   `proxy:"path-root,omitempty"`           // optional first-level path prefix for HTTP tunnel endpoints
	HTTPMaskMultiplex  string   `proxy:"http-mask-multiplex,omitempty"` // "off" (default), "auto" (reuse h1/h2), "on" (single tunnel, multi-target)
	CustomTable        string   `proxy:"custom-table,omitempty"`        // optional custom byte layout, e.g. xpxvvpvv
	CustomTables       []string `proxy:"custom-tables,omitempty"`       // optional table rotation patterns, overrides custom-table when non-empty
}

// DialContext implements C.ProxyAdapter
func (s *Sudoku) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	cfg, err := s.buildConfig(metadata)
	if err != nil {
		return nil, err
	}

	muxMode := normalizeHTTPMaskMultiplex(cfg.HTTPMaskMultiplex)
	if muxMode == "on" && !cfg.DisableHTTPMask && httpTunnelModeEnabled(cfg.HTTPMaskMode) {
		stream, muxErr := s.dialMultiplex(ctx, cfg.TargetAddress, muxMode)
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

	if _, err = c.Write(addrBuf); err != nil {
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

	if err = sudoku.WritePreface(c); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("send uot preface failed: %w", err)
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

	tableType := strings.ToLower(option.TableType)
	if tableType == "" {
		tableType = "prefer_ascii"
	}
	if tableType != "prefer_ascii" && tableType != "prefer_entropy" {
		return nil, fmt.Errorf("table-type must be prefer_ascii or prefer_entropy")
	}

	defaultConf := sudoku.DefaultConfig()
	paddingMin := defaultConf.PaddingMin
	paddingMax := defaultConf.PaddingMax
	if option.PaddingMin != nil {
		paddingMin = *option.PaddingMin
	}
	if option.PaddingMax != nil {
		paddingMax = *option.PaddingMax
	}
	if option.PaddingMin == nil && option.PaddingMax != nil && paddingMax < paddingMin {
		paddingMin = paddingMax
	}
	if option.PaddingMax == nil && option.PaddingMin != nil && paddingMax < paddingMin {
		paddingMax = paddingMin
	}
	enablePureDownlink := defaultConf.EnablePureDownlink
	if option.EnablePureDownlink != nil {
		enablePureDownlink = *option.EnablePureDownlink
	}

	baseConf := sudoku.ProtocolConfig{
		ServerAddress:           net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
		Key:                     option.Key,
		AEADMethod:              defaultConf.AEADMethod,
		PaddingMin:              paddingMin,
		PaddingMax:              paddingMax,
		EnablePureDownlink:      enablePureDownlink,
		HandshakeTimeoutSeconds: defaultConf.HandshakeTimeoutSeconds,
		DisableHTTPMask:         !option.HTTPMask,
		HTTPMaskMode:            defaultConf.HTTPMaskMode,
		HTTPMaskTLSEnabled:      option.HTTPMaskTLS,
		HTTPMaskHost:            option.HTTPMaskHost,
		HTTPMaskPathRoot:        strings.TrimSpace(option.PathRoot),
		HTTPMaskMultiplex:       defaultConf.HTTPMaskMultiplex,
	}
	if option.HTTPMaskMode != "" {
		baseConf.HTTPMaskMode = option.HTTPMaskMode
	}
	if option.HTTPMaskMultiplex != "" {
		baseConf.HTTPMaskMultiplex = option.HTTPMaskMultiplex
	}
	tables, err := sudoku.NewTablesWithCustomPatterns(sudoku.ClientAEADSeed(option.Key), tableType, option.CustomTable, option.CustomTables)
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
	case "stream", "poll", "auto":
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
		return sudoku.ClientHandshakeWithOptions(raw, &handshakeCfg, sudoku.ClientHandshakeOptions{})
	}

	var (
		c             net.Conn
		handshakeDone bool
	)
	if !cfg.DisableHTTPMask && httpTunnelModeEnabled(cfg.HTTPMaskMode) {
		muxMode := normalizeHTTPMaskMultiplex(cfg.HTTPMaskMultiplex)
		switch muxMode {
		case "auto", "on":
			client, errX := s.getOrCreateHTTPMaskClient(cfg)
			if errX != nil {
				return nil, errX
			}
			c, err = client.Dial(ctx, upgrade)
		default:
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
		c, err = sudoku.ClientHandshakeWithOptions(c, &handshakeCfg, sudoku.ClientHandshakeOptions{})
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (s *Sudoku) dialMultiplex(ctx context.Context, targetAddress string, mode string) (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		client, err := s.getOrCreateMuxClient(ctx, mode)
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

func (s *Sudoku) getOrCreateMuxClient(ctx context.Context, mode string) (*sudoku.MultiplexClient, error) {
	if s == nil {
		return nil, fmt.Errorf("nil adapter")
	}

	if mode == "auto" {
		s.muxMu.Lock()
		backoffUntil := s.muxBackoffUntil
		lastErr := s.muxLastErr
		s.muxMu.Unlock()
		if time.Now().Before(backoffUntil) {
			return nil, fmt.Errorf("multiplex temporarily disabled: %v", lastErr)
		}
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
		if mode == "auto" {
			s.muxLastErr = err
			s.muxBackoffUntil = time.Now().Add(45 * time.Second)
		}
		return nil, err
	}

	client, err := sudoku.StartMultiplexClient(baseConn)
	if err != nil {
		_ = baseConn.Close()
		if mode == "auto" {
			s.muxLastErr = err
			s.muxBackoffUntil = time.Now().Add(45 * time.Second)
		}
		return nil, err
	}

	s.muxClient = client
	return client, nil
}

func (s *Sudoku) noteMuxFailure(mode string, err error) {
	if mode != "auto" {
		return
	}
	s.muxMu.Lock()
	s.muxLastErr = err
	s.muxBackoffUntil = time.Now().Add(45 * time.Second)
	s.muxMu.Unlock()
}

func (s *Sudoku) resetMuxClient() {
	s.muxMu.Lock()
	defer s.muxMu.Unlock()
	if s.muxClient != nil {
		_ = s.muxClient.Close()
		s.muxClient = nil
	}
}

func (s *Sudoku) getOrCreateHTTPMaskClient(cfg *sudoku.ProtocolConfig) (*sudoku.HTTPMaskTunnelClient, error) {
	if s == nil {
		return nil, fmt.Errorf("nil adapter")
	}
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	s.httpMaskMu.Lock()
	defer s.httpMaskMu.Unlock()

	if s.httpMaskClient != nil {
		return s.httpMaskClient, nil
	}

	c, err := sudoku.NewHTTPMaskTunnelClient(cfg.ServerAddress, cfg, s.dialer.DialContext)
	if err != nil {
		return nil, err
	}
	s.httpMaskClient = c
	return c, nil
}

func (s *Sudoku) resetHTTPMaskClient() {
	s.httpMaskMu.Lock()
	defer s.httpMaskMu.Unlock()
	if s.httpMaskClient != nil {
		s.httpMaskClient.CloseIdleConnections()
		s.httpMaskClient = nil
	}
}
