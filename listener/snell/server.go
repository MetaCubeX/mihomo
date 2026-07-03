package snell

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	"github.com/metacubex/mihomo/transport/snell"

	shadowtls "github.com/metacubex/sing-shadowtls"
	"github.com/metacubex/sing/common"
	M "github.com/metacubex/sing/common/metadata"
)

const maxPacketLength = 0x3fff

type Listener struct {
	closed    bool
	config    LC.SnellServer
	listeners []net.Listener
	shadowTLS *shadowtls.Service
}

func New(config LC.SnellServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (C.MultiAddrListener, error) {
	if config.Version == 0 {
		config.Version = snell.Version4
	}
	if config.Version != snell.Version4 && config.Version != snell.Version5 {
		return nil, fmt.Errorf("snell inbound version %d is not supported", config.Version)
	}
	if config.Psk == "" {
		return nil, errors.New("snell inbound requires psk")
	}
	switch config.ObfsMode {
	case "", "http", "tls":
	default:
		return nil, fmt.Errorf("snell inbound obfs mode error: %s", config.ObfsMode)
	}

	l := &Listener{config: config}

	if config.ShadowTLS.Enable {
		buildHandshake := func(handshake LC.ShadowTLSHandshakeOptions) (handshakeConfig shadowtls.HandshakeConfig) {
			handshakeConfig.Server = M.ParseSocksaddr(handshake.Dest)
			handshakeConfig.Dialer = sing.NewDialer(tunnel, handshake.Proxy)
			return
		}
		var handshakeForServerName map[string]shadowtls.HandshakeConfig
		if config.ShadowTLS.Version > 1 {
			handshakeForServerName = make(map[string]shadowtls.HandshakeConfig)
			for serverName, serverOptions := range config.ShadowTLS.HandshakeForServerName {
				handshakeForServerName[serverName] = buildHandshake(serverOptions)
			}
		}
		var wildcardSNI shadowtls.WildcardSNI
		switch config.ShadowTLS.WildcardSNI {
		case "authed":
			wildcardSNI = shadowtls.WildcardSNIAuthed
		case "all":
			wildcardSNI = shadowtls.WildcardSNIAll
		default:
			wildcardSNI = shadowtls.WildcardSNIOff
		}
		var err error
		l.shadowTLS, err = shadowtls.NewService(shadowtls.ServiceConfig{
			Version:  config.ShadowTLS.Version,
			Password: config.ShadowTLS.Password,
			Users: common.Map(config.ShadowTLS.Users, func(it LC.ShadowTLSUser) shadowtls.User {
				return shadowtls.User{Name: it.Name, Password: it.Password}
			}),
			Handshake:              buildHandshake(config.ShadowTLS.Handshake),
			HandshakeForServerName: handshakeForServerName,
			StrictMode:             config.ShadowTLS.StrictMode,
			WildcardSNI:            wildcardSNI,
			Handler: sing.FnHandler{
				NewConnectionFn: func(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
					l.handleConn(conn, tunnel, sing.AdditionsFromContext(ctx)...)
					return nil
				}},
			Logger: log.SingLogger,
		})
		if err != nil {
			return nil, err
		}
	}
	for _, addr := range strings.Split(config.Listen, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			_ = l.Close()
			return nil, err
		}
		l.listeners = append(l.listeners, ln)
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					if l.closed {
						return
					}
					continue
				}
				go l.HandleConn(conn, tunnel, additions...)
			}
		}(ln)
	}
	return l, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, ln := range l.listeners {
		if err := ln.Close(); err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, ln := range l.listeners {
		addrList = append(addrList, ln.Addr())
	}
	return
}

func (l *Listener) HandleConn(rawConn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	defer rawConn.Close()
	conn := rawConn
	if l.shadowTLS != nil {
		ctx := sing.WithAdditions(context.TODO(), additions...)
		_ = l.shadowTLS.NewConnection(ctx, conn, M.Metadata{
			Protocol: "snell",
			Source:   M.SocksaddrFromNet(conn.RemoteAddr()),
		})
		return
	}
	l.handleConn(rawConn, tunnel, additions...)
}

func (l *Listener) handleConn(rawConn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	conn := rawConn
	switch l.config.ObfsMode {
	case "http":
		conn = obfs.NewHTTPObfsServer(conn)
	case "tls":
		conn = obfs.NewTLSObfsServer(conn)
	case "":
	default:
		return
	}
	stream := snell.ServerStreamConn(conn, []byte(l.config.Psk), l.config.Version)
	for {
		reuse, err := l.handleRequest(stream, tunnel, additions...)
		if err != nil || !reuse {
			return
		}
	}
}

func (l *Listener) handleRequest(stream *snell.Snell, tunnel C.Tunnel, additions ...inbound.Addition) (bool, error) {
	br := bufio.NewReader(stream)
	version, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if version != snell.Version {
		return false, fmt.Errorf("snell invalid protocol version: %d", version)
	}

	command, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if command == snell.CommandPing {
		_, _ = stream.Write([]byte{snell.CommandPong})
		return false, nil
	}

	clientID, err := readClientID(br)
	if err != nil {
		return false, err
	}

	switch command {
	case snell.CommandConnect, snell.CommandConnectV2:
		return l.handleTCP(stream, br, command == snell.CommandConnectV2, clientID, tunnel, additions...)
	case snell.CommandUDP:
		if !l.config.UDP {
			return false, errors.New("snell UDP is disabled")
		}
		return false, l.handleUDP(stream, clientID, tunnel, additions...)
	default:
		return false, fmt.Errorf("snell unknown command: %d", command)
	}
}

func readClientID(r *bufio.Reader) (string, error) {
	length, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	id := make([]byte, int(length))
	if _, err := io.ReadFull(r, id); err != nil {
		return "", err
	}
	return string(id), nil
}

func (l *Listener) handleTCP(stream *snell.Snell, br *bufio.Reader, reuse bool, clientID string, tunnel C.Tunnel, additions ...inbound.Addition) (bool, error) {
	hostLen, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if hostLen == 0 {
		return false, errors.New("snell connect host is empty")
	}

	hostBytes := make([]byte, int(hostLen))
	if _, err := io.ReadFull(br, hostBytes); err != nil {
		return false, err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return false, err
	}

	metadata := l.metadata(C.TCP, string(hostBytes), binary.BigEndian.Uint16(portBytes[:]), stream, clientID, additions...)
	conn := &tcpRequestConn{
		Conn:   stream,
		reader: br,
		reuse:  reuse,
	}
	tunnel.HandleTCPConn(conn, metadata)
	if !reuse {
		return false, nil
	}
	return true, nil
}

func (l *Listener) handleUDP(stream *snell.Snell, clientID string, tunnel C.Tunnel, additions ...inbound.Addition) error {
	if _, err := stream.Write([]byte{snell.CommandTunnel}); err != nil {
		return err
	}

	connID := utils.NewUUIDV4().String()
	localAddr := N.NewCustomAddr(C.SNELL.String(), connID, stream.RemoteAddr())
	writeMu := &sync.Mutex{}
	buf := make([]byte, maxPacketLength)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, shadowaead.ErrZeroChunk) {
				return nil
			}
			return err
		}
		request, err := snell.ParseUDPRequest(buf[:n])
		if err != nil {
			return err
		}
		metadata := l.metadata(C.UDP, request.Host, request.Port, stream, clientID, additions...)
		if request.Ip.IsValid() {
			metadata.Host = ""
			metadata.DstIP = request.Ip
		}

		payload := append([]byte(nil), request.Payload...)
		packet := &udpPacket{
			data:      payload,
			conn:      stream,
			writeMu:   writeMu,
			localAddr: localAddr,
			dstAddr:   metadata.UDPAddr(),
		}
		tunnel.HandleUDPPacket(packet, metadata)
	}
}

func (l *Listener) metadata(network C.NetWork, host string, port uint16, conn net.Conn, clientID string, additions ...inbound.Addition) *C.Metadata {
	metadata := &C.Metadata{
		NetWork: network,
		Type:    C.SNELL,
		DstPort: port,
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		metadata.DstIP = ip.Unmap()
	} else {
		metadata.Host = host
	}
	inbound.ApplyAdditions(metadata, inbound.WithSrcAddr(conn.RemoteAddr()), inbound.WithInAddr(conn.LocalAddr()))
	inbound.ApplyAdditions(metadata, additions...)
	if clientID != "" {
		inbound.ApplyAdditions(metadata, inbound.WithInUser(clientID))
	}
	return metadata
}

func writeCommandError(w io.Writer, code byte, message string) error {
	msg := []byte(message)
	if len(msg) > 255 {
		msg = msg[:255]
	}
	buf := make([]byte, 0, 3+len(msg))
	buf = append(buf, snell.CommandError, code, byte(len(msg)))
	buf = append(buf, msg...)
	_, err := w.Write(buf)
	return err
}

type tcpRequestConn struct {
	net.Conn
	reader       *bufio.Reader
	reuse        bool
	writeMu      sync.Mutex
	closeOnce    sync.Once
	replyWritten bool
}

func (c *tcpRequestConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if errors.Is(err, shadowaead.ErrZeroChunk) {
		err = io.EOF
	}
	return n, err
}

func (c *tcpRequestConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.replyWritten {
		payload := make([]byte, 1+len(p))
		payload[0] = snell.CommandTunnel
		copy(payload[1:], p)
		if _, err := c.Conn.Write(payload); err != nil {
			return 0, err
		}
		c.replyWritten = true
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *tcpRequestConn) CloseWrite() error {
	return c.Close()
}

func (c *tcpRequestConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()

		if !c.replyWritten {
			err = writeCommandError(c.Conn, 0x65, "Remote EOF")
			if !c.reuse {
				err = errors.Join(err, c.Conn.Close())
			}
			return
		}
		if c.reuse {
			_, err = c.Conn.Write(nil)
			return
		}
		err = c.Conn.Close()
	})
	return err
}

type udpPacket struct {
	data      []byte
	conn      *snell.Snell
	writeMu   *sync.Mutex
	localAddr net.Addr
	dstAddr   net.Addr
}

func (p *udpPacket) Data() []byte {
	return p.data
}

func (p *udpPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		addr = p.dstAddr
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return snell.WritePacketResponse(p.conn, addr, b)
}

func (p *udpPacket) Drop() {
	p.data = nil
}

func (p *udpPacket) LocalAddr() net.Addr {
	return p.localAddr
}

var _ C.MultiAddrListener = (*Listener)(nil)
var _ C.UDPPacket = (*udpPacket)(nil)
