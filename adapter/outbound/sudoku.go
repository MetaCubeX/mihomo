package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/saba-futai/sudoku/apis"
	"github.com/saba-futai/sudoku/pkg/crypto"
	sudokuobfs "github.com/saba-futai/sudoku/pkg/obfs/sudoku"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/sudoku"
)

type Sudoku struct {
	*Base
	option   *SudokuOption
	table    *sudokuobfs.Table
	baseConf apis.ProtocolConfig
}

type SudokuOption struct {
	BasicOption
	Name               string `proxy:"name"`
	Server             string `proxy:"server"`
	Port               int    `proxy:"port"`
	Key                string `proxy:"key"`
	AEADMethod         string `proxy:"aead-method,omitempty"`
	PaddingMin         *int   `proxy:"padding-min,omitempty"`
	PaddingMax         *int   `proxy:"padding-max,omitempty"`
	TableType          string `proxy:"table-type,omitempty"` // "prefer_ascii" or "prefer_entropy"
	EnablePureDownlink *bool  `proxy:"enable-pure-downlink,omitempty"`
	HTTPMask           bool   `proxy:"http-mask,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (s *Sudoku) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	cfg, err := s.buildConfig(metadata)
	if err != nil {
		return nil, err
	}

	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}

	defer func() {
		safeConnClose(c, err)
	}()

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	c, err = s.streamConn(c, cfg)
	if err != nil {
		return nil, err
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

	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}

	defer func() {
		safeConnClose(c, err)
	}()

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	c, err = s.handshakeConn(c, cfg)
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

func (s *Sudoku) buildConfig(metadata *C.Metadata) (*apis.ProtocolConfig, error) {
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

func (s *Sudoku) handshakeConn(rawConn net.Conn, cfg *apis.ProtocolConfig) (_ net.Conn, err error) {
	return sudoku.ClientHandshake(rawConn, cfg)
}

func (s *Sudoku) streamConn(rawConn net.Conn, cfg *apis.ProtocolConfig) (_ net.Conn, err error) {
	cConn, err := s.handshakeConn(rawConn, cfg)
	if err != nil {
		return nil, err
	}

	addrBuf, err := sudoku.EncodeAddress(cfg.TargetAddress)
	if err != nil {
		return nil, fmt.Errorf("encode target address failed: %w", err)
	}

	if _, err = cConn.Write(addrBuf); err != nil {
		cConn.Close()
		return nil, fmt.Errorf("send target address failed: %w", err)
	}

	return cConn, nil
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

	seed := option.Key
	if recoveredFromKey, err := crypto.RecoverPublicKey(option.Key); err == nil {
		seed = crypto.EncodePoint(recoveredFromKey)
	}

	start := time.Now()
	table := sudokuobfs.NewTable(seed, tableType)
	log.Infoln("[Sudoku] Tables initialized (%s) in %v", tableType, time.Since(start))

	defaultConf := apis.DefaultConfig()
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

	baseConf := apis.ProtocolConfig{
		ServerAddress:           net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
		Key:                     option.Key,
		AEADMethod:              defaultConf.AEADMethod,
		Table:                   table,
		PaddingMin:              paddingMin,
		PaddingMax:              paddingMax,
		EnablePureDownlink:      enablePureDownlink,
		HandshakeTimeoutSeconds: defaultConf.HandshakeTimeoutSeconds,
		DisableHTTPMask:         !option.HTTPMask,
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
		table:    table,
		baseConf: baseConf,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
