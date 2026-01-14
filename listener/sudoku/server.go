package sudoku

import (
	"errors"
	"io"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/sudoku"
)

type Listener struct {
	listener  net.Listener
	addr      string
	closed    bool
	protoConf sudoku.ProtocolConfig
	tunnelSrv *sudoku.HTTPMaskTunnelServer
	handler   *sing.ListenerHandler
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
	handshakeConn := conn
	handshakeCfg := &l.protoConf
	if l.tunnelSrv != nil {
		c, cfg, done, err := l.tunnelSrv.WrapConn(conn)
		if err != nil {
			_ = conn.Close()
			return
		}
		if done {
			return
		}
		if c != nil {
			handshakeConn = c
		}
		if cfg != nil {
			handshakeCfg = cfg
		}
	}

	session, err := sudoku.ServerHandshake(handshakeConn, handshakeCfg)
	if err != nil {
		_ = handshakeConn.Close()
		if handshakeConn != conn {
			_ = conn.Close()
		}
		return
	}

	switch session.Type {
	case sudoku.SessionTypeUoT:
		l.handleUoTSession(session.Conn, tunnel, additions...)
	case sudoku.SessionTypeMultiplex:
		mux, err := sudoku.AcceptMultiplexServer(session.Conn)
		if err != nil {
			_ = session.Conn.Close()
			return
		}
		defer mux.Close()

		for {
			stream, target, err := mux.AcceptTCP()
			if err != nil {
				return
			}
			targetAddr := socks5.ParseAddr(target)
			if targetAddr == nil {
				_ = stream.Close()
				continue
			}
			go l.handler.HandleSocket(targetAddr, stream, additions...)
		}
	default:
		targetAddr := socks5.ParseAddr(session.Target)
		if targetAddr == nil {
			_ = session.Conn.Close()
			return
		}
		l.handler.HandleSocket(targetAddr, session.Conn, additions...)
		//tunnel.HandleTCPConn(inbound.NewSocket(targetAddr, session.Conn, C.SUDOKU, additions...))
	}
}

func (l *Listener) handleUoTSession(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	writer := sudoku.NewUoTPacketConn(conn)
	remoteAddr := conn.RemoteAddr()

	for {
		addrStr, payload, err := sudoku.ReadDatagram(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Debugln("[Sudoku][UoT] session closed: %v", err)
			}
			_ = conn.Close()
			return
		}

		target := socks5.ParseAddr(addrStr)
		if target == nil {
			log.Debugln("[Sudoku][UoT] drop invalid target: %s", addrStr)
			continue
		}

		packet := &uotPacket{
			payload: payload,
			writer:  writer,
			rAddr:   remoteAddr,
		}
		tunnel.HandleUDPPacket(inbound.NewPacket(target, packet, C.SUDOKU, additions...))
	}
}

type uotPacket struct {
	payload []byte
	writer  *sudoku.UoTPacketConn
	rAddr   net.Addr
}

func (p *uotPacket) Data() []byte {
	return p.payload
}

func (p *uotPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	return p.writer.WriteTo(b, addr)
}

func (p *uotPacket) Drop() {
	p.payload = nil
}

func (p *uotPacket) LocalAddr() net.Addr {
	return p.rAddr
}

func New(config LC.SudokuServer, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-SUDOKU"),
			inbound.WithSpecialRules(""),
		}
	}

	// Using sing handler for sing-mux support
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.SUDOKU,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	l, err := inbound.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}

	tableType := strings.ToLower(config.TableType)
	if tableType == "" {
		tableType = "prefer_ascii"
	}

	defaultConf := sudoku.DefaultConfig()
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
	enablePureDownlink := defaultConf.EnablePureDownlink
	if config.EnablePureDownlink != nil {
		enablePureDownlink = *config.EnablePureDownlink
	}

	tables, err := sudoku.NewTablesWithCustomPatterns(config.Key, tableType, config.CustomTable, config.CustomTables)
	if err != nil {
		_ = l.Close()
		return nil, err
	}

	handshakeTimeout := defaultConf.HandshakeTimeoutSeconds
	if config.HandshakeTimeoutSecond != nil {
		handshakeTimeout = *config.HandshakeTimeoutSecond
	}

	protoConf := sudoku.ProtocolConfig{
		Key:                     config.Key,
		AEADMethod:              defaultConf.AEADMethod,
		PaddingMin:              paddingMin,
		PaddingMax:              paddingMax,
		EnablePureDownlink:      enablePureDownlink,
		HandshakeTimeoutSeconds: handshakeTimeout,
		DisableHTTPMask:         config.DisableHTTPMask,
		HTTPMaskMode:            config.HTTPMaskMode,
		HTTPMaskPathRoot:        strings.TrimSpace(config.PathRoot),
	}
	if len(tables) == 1 {
		protoConf.Table = tables[0]
	} else {
		protoConf.Tables = tables
	}
	if config.AEADMethod != "" {
		protoConf.AEADMethod = config.AEADMethod
	}

	sl := &Listener{
		listener:  l,
		addr:      config.Listen,
		protoConf: protoConf,
		handler:   h,
	}
	sl.tunnelSrv = sudoku.NewHTTPMaskTunnelServer(&sl.protoConf)

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
