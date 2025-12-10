package sudoku

import (
	"errors"
	"io"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/sudoku"
)

type Listener struct {
	listener  net.Listener
	addr      string
	closed    bool
	protoConf sudoku.ProtocolConfig
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
	session, err := sudoku.ServerHandshake(conn, &l.protoConf)
	if err != nil {
		_ = conn.Close()
		return
	}

	switch session.Type {
	case sudoku.SessionTypeUoT:
		l.handleUoTSession(session.Conn, tunnel, additions...)
	default:
		targetAddr := socks5.ParseAddr(session.Target)
		if targetAddr == nil {
			_ = session.Conn.Close()
			return
		}
		tunnel.HandleTCPConn(inbound.NewSocket(targetAddr, session.Conn, C.SUDOKU, additions...))
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

	table, err := sudoku.NewTableWithCustom(config.Key, tableType, config.CustomTable)
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
		Table:                   table,
		PaddingMin:              paddingMin,
		PaddingMax:              paddingMax,
		EnablePureDownlink:      enablePureDownlink,
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
