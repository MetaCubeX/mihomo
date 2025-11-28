package sudoku

import (
	"net"
	"strings"

	"github.com/saba-futai/sudoku/apis"
	sudokuobfs "github.com/saba-futai/sudoku/pkg/obfs/sudoku"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/socks5"
)

type Listener struct {
	listener  net.Listener
	addr      string
	closed    bool
	protoConf apis.ProtocolConfig
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	if l.listener == nil {
		return ""
	}
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

func (l *Listener) handleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	tunnelConn, target, err := apis.ServerHandshake(conn, &l.protoConf)
	if err != nil {
		_ = conn.Close()
		return
	}

	targetAddr := socks5.ParseAddr(target)
	if targetAddr == nil {
		_ = tunnelConn.Close()
		return
	}

	tunnel.HandleTCPConn(inbound.NewSocket(targetAddr, tunnelConn, C.SUDOKU, additions...))
}

func New(config LC.SudokuServer, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-SUDOKU"),
			inbound.WithSpecialRules(""),
		}
	}

	l, err := inbound.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}

	seed := config.Seed
	if seed == "" {
		seed = config.Key
	}

	tableType := strings.ToLower(config.TableType)
	if tableType == "" {
		tableType = "prefer_ascii"
	}

	table := sudokuobfs.NewTable(seed, tableType)

	defaultConf := apis.DefaultConfig()
	paddingMin := defaultConf.PaddingMin
	paddingMax := defaultConf.PaddingMax
	if config.PaddingMin != nil {
		paddingMin = *config.PaddingMin
	}
	if config.PaddingMax != nil {
		paddingMax = *config.PaddingMax
	}
	if config.PaddingMin == nil && config.PaddingMax != nil && paddingMax < paddingMin {
		paddingMin = paddingMax
	}
	if config.PaddingMax == nil && config.PaddingMin != nil && paddingMax < paddingMin {
		paddingMax = paddingMin
	}

	handshakeTimeout := defaultConf.HandshakeTimeoutSeconds
	if config.HandshakeTimeoutSecond != nil {
		handshakeTimeout = *config.HandshakeTimeoutSecond
	}

	protoConf := apis.ProtocolConfig{
		Key:                     config.Key,
		AEADMethod:              defaultConf.AEADMethod,
		Table:                   table,
		PaddingMin:              paddingMin,
		PaddingMax:              paddingMax,
		HandshakeTimeoutSeconds: handshakeTimeout,
	}
	if config.AEADMethod != "" {
		protoConf.AEADMethod = config.AEADMethod
	}

	sl := &Listener{
		listener:  l,
		addr:      config.Listen,
		protoConf: protoConf,
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			go sl.handleConn(c, tunnel, additions...)
		}
	}()

	return sl, nil
}
