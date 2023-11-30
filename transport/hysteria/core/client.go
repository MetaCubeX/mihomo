package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/hysteria/obfs"
	"github.com/metacubex/mihomo/transport/hysteria/pmtud_fix"
	"github.com/metacubex/mihomo/transport/hysteria/transport"
	"github.com/metacubex/mihomo/transport/hysteria/utils"

	"github.com/lunixbochs/struc"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/congestion"
	"github.com/zhangyunhao116/fastrand"
)

var (
	ErrClosed = errors.New("closed")
)

type CongestionFactory func(refBPS uint64) congestion.CongestionControl

type Client struct {
	transport         *transport.ClientTransport
	serverAddr        string
	serverPorts       string
	protocol          string
	sendBPS, recvBPS  uint64
	auth              []byte
	congestionFactory CongestionFactory
	obfuscator        obfs.Obfuscator

	tlsConfig  *tls.Config
	quicConfig *quic.Config

	quicSession    quic.Connection
	reconnectMutex sync.Mutex
	closed         bool

	udpSessionMutex sync.RWMutex
	udpSessionMap   map[uint32]chan *udpMessage
	udpDefragger    defragger
	hopInterval     time.Duration
	fastOpen        bool
}

func NewClient(serverAddr string, serverPorts string, protocol string, auth []byte, tlsConfig *tls.Config, quicConfig *quic.Config,
	transport *transport.ClientTransport, sendBPS uint64, recvBPS uint64, congestionFactory CongestionFactory,
	obfuscator obfs.Obfuscator, hopInterval time.Duration, fastOpen bool) (*Client, error) {
	quicConfig.DisablePathMTUDiscovery = quicConfig.DisablePathMTUDiscovery || pmtud_fix.DisablePathMTUDiscovery
	c := &Client{
		transport:         transport,
		serverAddr:        serverAddr,
		serverPorts:       serverPorts,
		protocol:          protocol,
		sendBPS:           sendBPS,
		recvBPS:           recvBPS,
		auth:              auth,
		congestionFactory: congestionFactory,
		obfuscator:        obfuscator,
		tlsConfig:         tlsConfig,
		quicConfig:        quicConfig,
		hopInterval:       hopInterval,
		fastOpen:          fastOpen,
	}
	return c, nil
}

func (c *Client) connectToServer(dialer utils.PacketDialer) error {
	qs, err := c.transport.QUICDial(c.protocol, c.serverAddr, c.serverPorts, c.tlsConfig, c.quicConfig, c.obfuscator, c.hopInterval, dialer)
	if err != nil {
		return err
	}
	// Control stream
	ctx, ctxCancel := context.WithTimeout(context.Background(), protocolTimeout)
	stream, err := qs.OpenStreamSync(ctx)
	ctxCancel()
	if err != nil {
		_ = qs.CloseWithError(closeErrorCodeProtocol, "protocol error")
		return err
	}
	ok, msg, err := c.handleControlStream(qs, stream)
	if err != nil {
		_ = qs.CloseWithError(closeErrorCodeProtocol, "protocol error")
		return err
	}
	if !ok {
		_ = qs.CloseWithError(closeErrorCodeAuth, "auth error")
		return fmt.Errorf("auth error: %s", msg)
	}
	// All good
	c.udpSessionMap = make(map[uint32]chan *udpMessage)
	go c.handleMessage(qs)
	c.quicSession = qs
	return nil
}

func (c *Client) handleControlStream(qs quic.Connection, stream quic.Stream) (bool, string, error) {
	// Send protocol version
	_, err := stream.Write([]byte{protocolVersion})
	if err != nil {
		return false, "", err
	}
	// Send client hello
	err = struc.Pack(stream, &clientHello{
		Rate: transmissionRate{
			SendBPS: c.sendBPS,
			RecvBPS: c.recvBPS,
		},
		Auth: c.auth,
	})
	if err != nil {
		return false, "", err
	}
	// Receive server hello
	var sh serverHello
	err = struc.Unpack(stream, &sh)
	if err != nil {
		return false, "", err
	}
	// Set the congestion accordingly
	if sh.OK && c.congestionFactory != nil {
		qs.SetCongestionControl(c.congestionFactory(sh.Rate.RecvBPS))
	}
	return sh.OK, sh.Message, nil
}

func (c *Client) handleMessage(qs quic.Connection) {
	for {
		msg, err := qs.ReceiveDatagram(context.Background())
		if err != nil {
			break
		}
		var udpMsg udpMessage
		err = struc.Unpack(bytes.NewBuffer(msg), &udpMsg)
		if err != nil {
			continue
		}
		dfMsg := c.udpDefragger.Feed(udpMsg)
		if dfMsg == nil {
			continue
		}
		c.udpSessionMutex.RLock()
		ch, ok := c.udpSessionMap[dfMsg.SessionID]
		if ok {
			select {
			case ch <- dfMsg:
				// OK
			default:
				// Silently drop the message when the channel is full
			}
		}
		c.udpSessionMutex.RUnlock()
	}
}

func (c *Client) openStreamWithReconnect(dialer utils.PacketDialer) (quic.Connection, quic.Stream, error) {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	if c.closed {
		return nil, nil, ErrClosed
	}
	if c.quicSession == nil {
		if err := c.connectToServer(dialer); err != nil {
			// Still error, oops
			return nil, nil, err
		}
	}
	stream, err := c.quicSession.OpenStream()
	if err == nil {
		// All good
		return c.quicSession, &wrappedQUICStream{stream}, nil
	}
	// Something is wrong
	if nErr, ok := err.(net.Error); ok && nErr.Temporary() {
		// Temporary error, just return
		return nil, nil, err
	}
	// Permanent error, need to reconnect
	if err := c.connectToServer(dialer); err != nil {
		// Still error, oops
		return nil, nil, err
	}
	// We are not going to try again even if it still fails the second time
	stream, err = c.quicSession.OpenStream()
	return c.quicSession, &wrappedQUICStream{stream}, err
}

func (c *Client) DialTCP(host string, port uint16, dialer utils.PacketDialer) (net.Conn, error) {
	session, stream, err := c.openStreamWithReconnect(dialer)
	if err != nil {
		return nil, err
	}
	// Send request
	err = struc.Pack(stream, &clientRequest{
		UDP:  false,
		Host: host,
		Port: port,
	})
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	// If fast open is enabled, we return the stream immediately
	// and defer the response handling to the first Read() call
	if !c.fastOpen {
		// Read response
		var sr serverResponse
		err = struc.Unpack(stream, &sr)
		if err != nil {
			_ = stream.Close()
			return nil, err
		}
		if !sr.OK {
			_ = stream.Close()
			return nil, fmt.Errorf("connection rejected: %s", sr.Message)
		}
	}

	return &quicConn{
		Orig:             stream,
		PseudoLocalAddr:  session.LocalAddr(),
		PseudoRemoteAddr: session.RemoteAddr(),
		Established:      !c.fastOpen,
	}, nil
}

func (c *Client) DialUDP(dialer utils.PacketDialer) (UDPConn, error) {
	session, stream, err := c.openStreamWithReconnect(dialer)
	if err != nil {
		return nil, err
	}
	// Send request
	err = struc.Pack(stream, &clientRequest{
		UDP: true,
	})
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	// Read response
	var sr serverResponse
	err = struc.Unpack(stream, &sr)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if !sr.OK {
		_ = stream.Close()
		return nil, fmt.Errorf("connection rejected: %s", sr.Message)
	}

	// Create a session in the map
	c.udpSessionMutex.Lock()
	nCh := make(chan *udpMessage, 1024)
	// Store the current session map for CloseFunc below
	// to ensures that we are adding and removing sessions on the same map,
	// as reconnecting will reassign the map
	sessionMap := c.udpSessionMap
	sessionMap[sr.UDPSessionID] = nCh
	c.udpSessionMutex.Unlock()

	pktConn := &quicPktConn{
		Session: session,
		Stream:  stream,
		CloseFunc: func() {
			c.udpSessionMutex.Lock()
			if ch, ok := sessionMap[sr.UDPSessionID]; ok {
				close(ch)
				delete(sessionMap, sr.UDPSessionID)
			}
			c.udpSessionMutex.Unlock()
		},
		UDPSessionID: sr.UDPSessionID,
		MsgCh:        nCh,
	}
	go pktConn.Hold()
	return pktConn, nil
}

func (c *Client) Close() error {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	err := c.quicSession.CloseWithError(closeErrorCodeGeneric, "")
	c.closed = true
	return err
}

type quicConn struct {
	Orig             quic.Stream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
}

func (w *quicConn) Read(b []byte) (n int, err error) {
	if !w.Established {
		var sr serverResponse
		err := struc.Unpack(w.Orig, &sr)
		if err != nil {
			_ = w.Close()
			return 0, err
		}
		if !sr.OK {
			_ = w.Close()
			return 0, fmt.Errorf("connection rejected: %s", sr.Message)
		}
		w.Established = true
	}
	return w.Orig.Read(b)
}

func (w *quicConn) Write(b []byte) (n int, err error) {
	return w.Orig.Write(b)
}

func (w *quicConn) Close() error {
	return w.Orig.Close()
}

func (w *quicConn) LocalAddr() net.Addr {
	return w.PseudoLocalAddr
}

func (w *quicConn) RemoteAddr() net.Addr {
	return w.PseudoRemoteAddr
}

func (w *quicConn) SetDeadline(t time.Time) error {
	return w.Orig.SetDeadline(t)
}

func (w *quicConn) SetReadDeadline(t time.Time) error {
	return w.Orig.SetReadDeadline(t)
}

func (w *quicConn) SetWriteDeadline(t time.Time) error {
	return w.Orig.SetWriteDeadline(t)
}

type UDPConn interface {
	ReadFrom() ([]byte, string, error)
	WriteTo([]byte, string) error
	Close() error
	LocalAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type quicPktConn struct {
	Session      quic.Connection
	Stream       quic.Stream
	CloseFunc    func()
	UDPSessionID uint32
	MsgCh        <-chan *udpMessage
}

func (c *quicPktConn) Hold() {
	// Hold the stream until it's closed
	buf := make([]byte, 1024)
	for {
		_, err := c.Stream.Read(buf)
		if err != nil {
			break
		}
	}
	_ = c.Close()
}

func (c *quicPktConn) ReadFrom() ([]byte, string, error) {
	msg := <-c.MsgCh
	if msg == nil {
		// Closed
		return nil, "", ErrClosed
	}
	return msg.Data, net.JoinHostPort(msg.Host, strconv.Itoa(int(msg.Port))), nil
}

func (c *quicPktConn) WriteTo(p []byte, addr string) error {
	host, port, err := utils.SplitHostPort(addr)
	if err != nil {
		return err
	}
	msg := udpMessage{
		SessionID: c.UDPSessionID,
		Host:      host,
		Port:      port,
		FragCount: 1,
		Data:      p,
	}
	// try no frag first
	var msgBuf bytes.Buffer
	_ = struc.Pack(&msgBuf, &msg)
	err = c.Session.SendDatagram(msgBuf.Bytes())
	if err != nil {
		if errSize, ok := err.(quic.ErrMessageTooLarge); ok {
			// need to frag
			msg.MsgID = uint16(fastrand.Intn(0xFFFF)) + 1 // msgID must be > 0 when fragCount > 1
			fragMsgs := fragUDPMessage(msg, int(errSize))
			for _, fragMsg := range fragMsgs {
				msgBuf.Reset()
				_ = struc.Pack(&msgBuf, &fragMsg)
				err = c.Session.SendDatagram(msgBuf.Bytes())
				if err != nil {
					return err
				}
			}
			return nil
		} else {
			// some other error
			return err
		}
	} else {
		return nil
	}
}

func (c *quicPktConn) Close() error {
	c.CloseFunc()
	return c.Stream.Close()
}

func (c *quicPktConn) LocalAddr() net.Addr {
	return c.Session.LocalAddr()
}

func (c *quicPktConn) SetDeadline(t time.Time) error {
	return c.Stream.SetDeadline(t)
}

func (c *quicPktConn) SetReadDeadline(t time.Time) error {
	return c.Stream.SetReadDeadline(t)
}

func (c *quicPktConn) SetWriteDeadline(t time.Time) error {
	return c.Stream.SetWriteDeadline(t)
}
