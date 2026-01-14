package inbound

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sudoku"
	"github.com/metacubex/mihomo/log"
)

type SudokuOption struct {
	BaseOption
	Key                    string   `inbound:"key"`
	AEADMethod             string   `inbound:"aead-method,omitempty"`
	PaddingMin             *int     `inbound:"padding-min,omitempty"`
	PaddingMax             *int     `inbound:"padding-max,omitempty"`
	TableType              string   `inbound:"table-type,omitempty"` // "prefer_ascii" or "prefer_entropy"
	HandshakeTimeoutSecond *int     `inbound:"handshake-timeout,omitempty"`
	EnablePureDownlink     *bool    `inbound:"enable-pure-downlink,omitempty"`
	CustomTable            string   `inbound:"custom-table,omitempty"` // optional custom byte layout, e.g. xpxvvpvv
	CustomTables           []string `inbound:"custom-tables,omitempty"`
	DisableHTTPMask        bool     `inbound:"disable-http-mask,omitempty"`
	HTTPMaskMode           string   `inbound:"http-mask-mode,omitempty"` // "legacy" (default), "stream", "poll", "auto"
	PathRoot               string   `inbound:"path-root,omitempty"`      // optional first-level path prefix for HTTP tunnel endpoints

	// mihomo private extension (not the part of standard Sudoku protocol)
	MuxOption MuxOption `inbound:"mux-option,omitempty"`
}

func (o SudokuOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Sudoku struct {
	*Base
	config     *SudokuOption
	listeners  []*sudoku.Listener
	serverConf LC.SudokuServer
}

func NewSudoku(options *SudokuOption) (*Sudoku, error) {
	if options.Key == "" {
		return nil, fmt.Errorf("sudoku inbound requires key")
	}
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}

	serverConf := LC.SudokuServer{
		Enable:                 true,
		Listen:                 base.RawAddress(),
		Key:                    options.Key,
		AEADMethod:             options.AEADMethod,
		PaddingMin:             options.PaddingMin,
		PaddingMax:             options.PaddingMax,
		TableType:              options.TableType,
		HandshakeTimeoutSecond: options.HandshakeTimeoutSecond,
		EnablePureDownlink:     options.EnablePureDownlink,
		CustomTable:            options.CustomTable,
		CustomTables:           options.CustomTables,
		DisableHTTPMask:        options.DisableHTTPMask,
		HTTPMaskMode:           options.HTTPMaskMode,
		PathRoot:               strings.TrimSpace(options.PathRoot),
	}
	serverConf.MuxOption = options.MuxOption.Build()

	return &Sudoku{
		Base:       base,
		config:     options,
		serverConf: serverConf,
	}, nil
}

// Config implements constant.InboundListener
func (s *Sudoku) Config() C.InboundConfig {
	return s.config
}

// Address implements constant.InboundListener
func (s *Sudoku) Address() string {
	var addrList []string
	for _, l := range s.listeners {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (s *Sudoku) Listen(tunnel C.Tunnel) error {
	if s.serverConf.Key == "" {
		return fmt.Errorf("sudoku inbound requires key")
	}

	var errs []error
	for _, addr := range strings.Split(s.RawAddress(), ",") {
		conf := s.serverConf
		conf.Listen = addr

		l, err := sudoku.New(conf, tunnel, s.Additions()...)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.listeners = append(s.listeners, l)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	log.Infoln("Sudoku[%s] inbound listening at: %s", s.Name(), s.Address())
	return nil
}

// Close implements constant.InboundListener
func (s *Sudoku) Close() error {
	var errs []error
	for _, l := range s.listeners {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*Sudoku)(nil)
