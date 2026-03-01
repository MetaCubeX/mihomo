package sudoku

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inner"
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
	fallback  string
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
	log.Debugln("[Sudoku] accepted %s", conn.RemoteAddr())
	handshakeConn := conn
	handshakeCfg := &l.protoConf
	closeConns := func() {
		_ = handshakeConn.Close()
		if handshakeConn != conn {
			_ = conn.Close()
		}
	}
	if l.tunnelSrv != nil {
		c, cfg, done, err := l.tunnelSrv.WrapConn(conn)
		if err != nil {
			closeConns()
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

	if l.fallback != "" {
		if r, ok := handshakeConn.(interface{ IsHTTPMaskRejected() bool }); ok && r.IsHTTPMaskRejected() {
			fb, err := inner.HandleTcp(tunnel, l.fallback, "")
			if err != nil {
				closeConns()
				return
			}
			N.Relay(handshakeConn, fb)
			return
		}
	}

	cConn, meta, err := sudoku.ServerHandshake(handshakeConn, handshakeCfg)
	if err != nil {
		fallbackAddr := l.fallback
		var susp *sudoku.SuspiciousError
		isSuspicious := errors.As(err, &susp) && susp != nil && susp.Conn != nil
		if isSuspicious {
			log.Warnln("[Sudoku] suspicious handshake from %s: %v", conn.RemoteAddr(), err)
			if fallbackAddr != "" {
				fb, err := inner.HandleTcp(tunnel, fallbackAddr, "")
				if err == nil {
					relayToFallback(susp.Conn, conn, fb)
					return
				}
			}
		} else {
			log.Debugln("[Sudoku] handshake failed from %s: %v", conn.RemoteAddr(), err)
		}
		closeConns()
		return
	}

	session, err := sudoku.ReadServerSession(cConn, meta)
	if err != nil {
		log.Warnln("[Sudoku] read session failed from %s: %v", conn.RemoteAddr(), err)
		_ = cConn.Close()
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
			log.Warnln("[Sudoku] invalid target from %s: %q", conn.RemoteAddr(), session.Target)
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
	connID := utils.NewUUIDV4().String() // make a new SNAT key

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

		cPacket := &uotPacket{
			payload: payload,
			writer:  writer,
			rAddr:   remoteAddr,
		}
		cPacket.rAddr = N.NewCustomAddr(C.SUDOKU.String(), connID, cPacket.rAddr) // for tunnel's handleUDPConn
		tunnel.HandleUDPPacket(inbound.NewPacket(target, cPacket, C.SUDOKU, additions...))
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

func relayToFallback(wrapper net.Conn, rawConn net.Conn, fallback net.Conn) {
	if wrapper != nil {
		if recorder, ok := wrapper.(interface{ GetBufferedAndRecorded() []byte }); ok {
			badData := recorder.GetBufferedAndRecorded()
			if len(badData) > 0 {
				_ = fallback.SetWriteDeadline(time.Now().Add(3 * time.Second))
				if _, err := io.Copy(fallback, bytes.NewReader(badData)); err != nil {
					_ = fallback.Close()
					_ = rawConn.Close()
					return
				}
				_ = fallback.SetWriteDeadline(time.Time{})
			}
		}
	}
	N.Relay(rawConn, fallback)
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

	tableType, err := sudoku.NormalizeTableType(config.TableType)
	if err != nil {
		_ = l.Close()
		return nil, err
	}

	defaultConf := sudoku.DefaultConfig()
	paddingMin, paddingMax := sudoku.ResolvePadding(config.PaddingMin, config.PaddingMax, defaultConf.PaddingMin, defaultConf.PaddingMax)
	enablePureDownlink := sudoku.DerefBool(config.EnablePureDownlink, defaultConf.EnablePureDownlink)

	tables, err := sudoku.NewServerTablesWithCustomPatterns(sudoku.ServerAEADSeed(config.Key), tableType, config.CustomTable, config.CustomTables)
	if err != nil {
		_ = l.Close()
		return nil, err
	}

	handshakeTimeout := sudoku.DerefInt(config.HandshakeTimeoutSecond, defaultConf.HandshakeTimeoutSeconds)

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
		fallback:  strings.TrimSpace(config.Fallback),
	}
	if sl.fallback != "" {
		sl.tunnelSrv = sudoku.NewHTTPMaskTunnelServerWithFallback(&sl.protoConf)
	} else {
		sl.tunnelSrv = sudoku.NewHTTPMaskTunnelServer(&sl.protoConf)
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
