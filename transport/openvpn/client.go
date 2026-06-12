package openvpn

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tls"
	"golang.org/x/sync/semaphore"
)

const (
	DefaultHandshakeTimeout = 30 * time.Second
	ControlRetransmitDelay  = time.Second
	DefaultControlPollDelay = time.Second
	dataChannelRekeyOverlap = ControlRetransmitDelay
)

var (
	ErrControlRestart   = errors.New("openvpn control channel requested restart")
	ErrControlSoftReset = errors.New("openvpn control channel requested soft reset")
)

type controlStream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type controlLoopHooks struct {
	rekey func(context.Context, string) (*PushReply, controlStream, error)
}

type Client struct {
	config *ClientConfig
	mux    *PacketMux

	control  *ControlChannel
	tlsConn  *tls.Conn
	data     *DataChannel
	push     *PushReply
	activity *remoteActivity

	cancel context.CancelFunc

	writeSem semaphore.Weighted

	lastSendNano    atomic.Int64
	lastReceiveNano atomic.Int64
}

type remoteActivity struct {
	lastUnixNano atomic.Int64
}

func newRemoteActivity() *remoteActivity {
	activity := &remoteActivity{}
	activity.Mark()
	return activity
}

func (a *remoteActivity) Mark() {
	if a == nil {
		return
	}
	a.lastUnixNano.Store(time.Now().UnixNano())
}

func (a *remoteActivity) Last() time.Time {
	if a == nil {
		return time.Now()
	}
	nanos := a.lastUnixNano.Load()
	if nanos == 0 {
		return time.Now()
	}
	return time.Unix(0, nanos)
}

func NewClient(config *ClientConfig, io PacketIO) (*Client, error) {
	if config == nil {
		return nil, errors.New("nil openvpn client config")
	}
	if io == nil {
		return nil, errors.New("nil openvpn packet io")
	}
	var crypt ControlProtection
	if len(config.TLSCryptKey) > 0 {
		var err error
		crypt, err = NewTLSCrypt(config.TLSCryptKey, true)
		if err != nil {
			return nil, err
		}
		log.Debugln("[OpenVPN] control protection=tls-crypt remote=%s", config.RemoteAddress())
	} else if len(config.TLSAuthKey) > 0 {
		var err error
		crypt, err = NewTLSAuth(config.TLSAuthKey, config.Auth, config.TLSAuthDirection, true)
		if err != nil {
			return nil, err
		}
		log.Debugln("[OpenVPN] control protection=tls-auth auth=%s key-direction=%d remote=%s", config.Auth, config.TLSAuthDirection, config.RemoteAddress())
	} else {
		log.Debugln("[OpenVPN] control protection=none remote=%s", config.RemoteAddress())
	}
	local, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	mux := NewPacketMux(io)
	go mux.Run(runCtx)
	client := &Client{
		config:   config,
		mux:      mux,
		control:  NewControlChannel(mux, crypt, local),
		activity: newRemoteActivity(),
		cancel:   cancel,
	}
	client.markSend()
	client.markReceive()
	return client, nil
}

func (c *Client) Handshake(ctx context.Context) (*PushReply, error) {
	if c == nil {
		return nil, errors.New("nil openvpn client")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultHandshakeTimeout)
		defer cancel()
	}
	log.Debugln("[OpenVPN] sending hard reset to %s", c.config.RemoteAddress())
	if err := c.control.SendReset(ctx); err != nil {
		return nil, fmt.Errorf("send hard reset: %w", err)
	}
	log.Debugln("[OpenVPN] waiting for hard reset response from %s", c.config.RemoteAddress())
	if err := c.waitServerReset(ctx); err != nil {
		return nil, err
	}
	log.Debugln("[OpenVPN] hard reset response received from %s", c.config.RemoteAddress())

	return c.negotiateDataSession(ctx, false)
}

func (c *Client) Renegotiate(ctx context.Context, reason string) (*PushReply, error) {
	if c == nil {
		return nil, errors.New("nil openvpn client")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultHandshakeTimeout)
		defer cancel()
	}
	log.Debugln("[OpenVPN] starting soft reset for %s: %s", c.config.RemoteAddress(), reason)
	if err := c.control.SendSoftReset(ctx); err != nil {
		return nil, fmt.Errorf("send soft reset: %w", err)
	}
	return c.negotiateDataSession(ctx, true)
}

func (c *Client) negotiateDataSession(ctx context.Context, rekey bool) (*PushReply, error) {
	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	controlConn := NewControlConn(c.control)
	if rekey {
		controlConn = NewSoftResetControlConn(c.control)
	}
	c.tlsConn = tls.Client(controlConn, tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.tlsConn.SetDeadline(deadline)
	}
	log.Debugln("[OpenVPN] starting TLS handshake with %s", c.config.RemoteAddress())
	if err := c.tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("openvpn tls handshake: %w", err)
	}
	log.Debugln("[OpenVPN] TLS handshake complete with %s", c.config.RemoteAddress())

	clientRecord, err := NewClientKeyMethod2Record(
		InstallScriptOptionsString(c.config.Proto, c.config.Cipher, c.config.Auth, c.config.CompLZO, len(c.config.TLSAuthKey) > 0, c.config.TLSAuthDirection),
		InstallScriptPeerInfo(c.config.Cipher, c.config.CompLZO),
		strings.TrimSpace(c.config.Username),
		c.config.Password,
	)
	if err != nil {
		return nil, err
	}
	clientBytes, err := clientRecord.MarshalClient()
	if err != nil {
		return nil, err
	}
	if _, err := c.tlsConn.Write(clientBytes); err != nil {
		return nil, fmt.Errorf("write key method 2 client record: %w", err)
	}
	log.Debugln("[OpenVPN] waiting for key method 2 server record from %s", c.config.RemoteAddress())
	serverRecord, err := c.readServerKeyMethod(ctx)
	if err != nil {
		return nil, err
	}
	log.Debugln("[OpenVPN] key method 2 server record received from %s", c.config.RemoteAddress())

	sources := clientRecord.Sources
	sources.Server = serverRecord.Sources.Server
	keys, err := DeriveClientKeyMaterial(sources, c.control.LocalSessionID(), c.control.RemoteSessionID(), c.config.DataCipherKeyLength())
	if err != nil {
		return nil, fmt.Errorf("derive data channel keys: %w", err)
	}

	if _, err := c.tlsConn.Write([]byte(PushRequest + "\x00")); err != nil {
		return nil, fmt.Errorf("write push request: %w", err)
	}
	log.Debugln("[OpenVPN] waiting for push reply from %s", c.config.RemoteAddress())
	push, err := c.readPushReply(ctx)
	if err != nil {
		return nil, err
	}
	log.Debugln("[OpenVPN] push reply received from %s", c.config.RemoteAddress())
	if err := c.installDataChannel(keys, push, rekey); err != nil {
		return nil, err
	}
	_ = c.tlsConn.SetDeadline(time.Time{})
	return push, nil
}

func (c *Client) installDataChannel(keys *KeyMaterial, push *PushReply, rekey bool) error {
	if c == nil {
		return errors.New("nil openvpn client")
	}
	if push == nil {
		return errors.New("nil openvpn push reply")
	}
	if rekey && c.data != nil {
		if err := c.data.Rekey(keys, c.config.Cipher, c.config.Auth, push.PeerID, c.config.CompLZO); err != nil {
			return err
		}
		c.schedulePreviousKeyRetirement()
	} else {
		data, err := NewDataChannel(keys, c.config.Cipher, c.config.Auth, push.PeerID, c.config.CompLZO)
		if err != nil {
			return err
		}
		c.data = data
	}
	c.push = push
	c.activity.Mark()
	return nil
}

func (c *Client) schedulePreviousKeyRetirement() {
	if c == nil || c.data == nil {
		return
	}
	data := c.data
	generation, ok := data.activeGeneration()
	if !ok {
		return
	}
	time.AfterFunc(dataChannelRekeyOverlap, func() {
		data.RetirePreviousKeysForGeneration(generation)
	})
}

func (c *Client) RunControlLoop(ctx context.Context) error {
	if c == nil {
		return errors.New("nil openvpn client")
	}
	if c.tlsConn == nil || c.push == nil {
		return errors.New("openvpn control channel is not ready")
	}
	return runControlLoopWithHooks(ctx, c.tlsConn, c.push, c.config.RemoteAddress(), c.activity, controlLoopHooks{
		rekey: func(ctx context.Context, reason string) (*PushReply, controlStream, error) {
			push, err := c.Renegotiate(ctx, reason)
			if err != nil {
				return nil, nil, err
			}
			return push, c.tlsConn, nil
		},
	})
}

func (c *Client) WriteIPPacket(ctx context.Context, packet []byte) error {
	return c.writeDataPacket(ctx, packet, true)
}

func (c *Client) WritePing(ctx context.Context) error {
	return c.writeDataPacket(ctx, openVPNPingPacket, false)
}

func (c *Client) writeDataPacket(ctx context.Context, packet []byte, compress bool) error {
	if c.data == nil {
		return errors.New("openvpn data channel is not ready")
	}
	if err := c.writeSem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer c.writeSem.Release(1)
	if compress && c.config.CompLZO == CompLzoYes {
		compressed, err := lzo1xCompressSafe(packet)
		if err != nil {
			return err
		}
		packet = compressed
	}
	encrypted, err := c.data.Encrypt(packet)
	if err != nil {
		return err
	}
	err = c.mux.WritePacket(ctx, encrypted)
	if err != nil {
		return err
	}
	c.markSend()
	return nil
}

func (c *Client) ReadIPPacket(ctx context.Context) ([]byte, error) {
	if c.data == nil {
		return nil, errors.New("openvpn data channel is not ready")
	}
	for {
		packet, err := c.mux.ReadDataPacket(ctx)
		if err != nil {
			return nil, err
		}
		plain, err := c.data.Decrypt(packet)
		if err != nil {
			continue
		}
		c.markReceive()
		c.activity.Mark()
		if IsPingPacket(plain) {
			continue
		}
		if c.config.CompLZO == CompLzoYes && len(plain) > 0 {
			return lzo1xDecompressSafe(plain)
		}
		return plain, nil
	}
}

func (c *Client) SinceSend() time.Duration {
	return time.Duration(int64(time.Since(start)) - c.lastSendNano.Load())
}

func (c *Client) SinceReceive() time.Duration {
	return time.Duration(int64(time.Since(start)) - c.lastReceiveNano.Load())
}

func (c *Client) markSend() {
	c.lastSendNano.Store(int64(time.Since(start)))
}

func (c *Client) markReceive() {
	c.lastReceiveNano.Store(int64(time.Since(start)))
}

// The absolute value doesn't matter, but it should be in the past,
// so that every timestamp obtained with Now() is non-zero,
// even on systems with low timer resolutions (e.g. Windows).
var start = time.Now().Add(-time.Hour)

func (c *Client) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.tlsConn != nil {
		_ = c.tlsConn.Close()
	}
	if c.mux != nil {
		return c.mux.Close()
	}
	return nil
}

func (c *Client) waitServerReset(ctx context.Context) error {
	retransmits := 0
	for {
		readCtx := ctx
		cancel := func() {}
		if c.config.Proto == ProtoUDP {
			readCtx, cancel = context.WithTimeout(ctx, ControlRetransmitDelay)
		}
		packet, err := c.control.Read(readCtx)
		cancel()
		if err != nil {
			if c.config.Proto == ProtoUDP && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				if err := c.control.RetransmitPending(ctx); err != nil {
					return fmt.Errorf("retransmit hard reset: %w", err)
				}
				retransmits++
				continue
			}
			return fmt.Errorf("read hard reset response after %d retransmits: %w", retransmits, err)
		}
		switch packet.Opcode {
		case PControlHardResetServerV2:
			return c.control.SendAck(ctx)
		case PControlHardResetServerV1:
			return fmt.Errorf("openvpn server replied with unsupported key method 1 reset")
		}
	}
}

func (c *Client) readServerKeyMethod(ctx context.Context) (*KeyMethod2Record, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.tlsConn.SetReadDeadline(deadline)
		}
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			return nil, fmt.Errorf("read key method 2 server record: %w", err)
		}
		buf = append(buf, tmp[:n]...)
		record, err := ParseServerKeyMethod2Record(buf)
		if err == nil {
			return record, nil
		}
		if !strings.Contains(err.Error(), "truncated") && !errors.Is(err, ioStringEOF) {
			return nil, err
		}
	}
}

func (c *Client) readPushReply(ctx context.Context) (*PushReply, error) {
	var buf []byte
	var pushOptions []string
	tmp := make([]byte, 4096)
	retransmits := 0
	for {
		if deadline, ok := ctx.Deadline(); ok {
			readDeadline := time.Now().Add(ControlRetransmitDelay)
			if deadline.Before(readDeadline) {
				readDeadline = deadline
			}
			_ = c.tlsConn.SetReadDeadline(readDeadline)
		}
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && ctx.Err() == nil {
				if _, writeErr := c.tlsConn.Write([]byte(PushRequest + "\x00")); writeErr != nil {
					return nil, fmt.Errorf("retransmit push request after %d retransmits: %w", retransmits, writeErr)
				}
				retransmits++
				continue
			}
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				break
			}
			return nil, fmt.Errorf("read push reply after %d retransmits: %w", retransmits, err)
		}
		buf = append(buf, tmp[:n]...)
		if bytes.Contains(buf, []byte("\x00")) || strings.Contains(string(buf), "PUSH_REPLY") {
			msg := string(buf)
			if idx := strings.IndexByte(msg, 0); idx >= 0 {
				msg = msg[:idx]
			}
			if strings.HasPrefix(msg, "PUSH_REPLY") {
				options, continuation := splitPushReplyOptions(msg)
				pushOptions = append(pushOptions, options...)
				buf = nil
				if continuation == 2 {
					continue
				}
				return ParsePushReply(joinPushReplyOptions(pushOptions))
			}
			if strings.HasPrefix(msg, "AUTH_FAILED") {
				return nil, fmt.Errorf("openvpn authentication failed: %s", msg)
			}
			if strings.HasPrefix(msg, "AUTH_PENDING") {
				log.Debugln("[OpenVPN] auth pending from %s: %s", c.config.RemoteAddress(), msg)
				buf = nil
				continue
			}
			if strings.TrimSpace(msg) != "" {
				return nil, fmt.Errorf("unexpected openvpn control message while waiting for push reply: %s", msg)
			}
		}
	}
	return nil, ctx.Err()
}

func runControlLoop(ctx context.Context, stream controlStream, push *PushReply, remote string, activity *remoteActivity) error {
	return runControlLoopWithHooks(ctx, stream, push, remote, activity, controlLoopHooks{})
}

func runControlLoopWithHooks(ctx context.Context, stream controlStream, push *PushReply, remote string, activity *remoteActivity, hooks controlLoopHooks) error {
	if push == nil {
		return errors.New("nil openvpn push reply")
	}
	pingInterval := push.PingInterval
	if pingInterval <= 0 && push.PingRestart > 0 {
		pingInterval = push.PingRestart / 2
	}
	pingRestart := push.PingRestart
	renegotiateAt := time.Time{}
	if push.RenegotiateAfter > 0 {
		renegotiateAt = time.Now().Add(push.RenegotiateAfter)
	}

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	lastReceived := activity.Last()
	lastPingSent := time.Now()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := time.Now()
		lastReceived = activity.Last()
		if !renegotiateAt.IsZero() && !now.Before(renegotiateAt) {
			nextPush, nextStream, err := runControlLoopRekey(ctx, hooks, "reneg-sec elapsed")
			if err != nil {
				return err
			}
			if nextStream != nil {
				stream = nextStream
			}
			push = nextPush
			pingInterval = push.PingInterval
			if pingInterval <= 0 && push.PingRestart > 0 {
				pingInterval = push.PingRestart / 2
			}
			pingRestart = push.PingRestart
			renegotiateAt = time.Time{}
			if push.RenegotiateAfter > 0 {
				renegotiateAt = time.Now().Add(push.RenegotiateAfter)
			}
			lastReceived = activity.Last()
			lastPingSent = time.Now()
			continue
		}
		if pingRestart > 0 && !lastReceived.Add(pingRestart).After(now) {
			return fmt.Errorf("%w: ping-restart elapsed without control traffic from %s", ErrControlRestart, remote)
		}
		if pingInterval > 0 && !lastPingSent.Add(pingInterval).After(now) {
			if err := writeControlMessage(ctx, stream, "PING"); err != nil {
				return fmt.Errorf("write openvpn ping: %w", err)
			}
			lastPingSent = time.Now()
		}

		deadline := nextControlDeadline(time.Now(), lastReceived, lastPingSent, pingInterval, pingRestart, renegotiateAt)
		if err := stream.SetReadDeadline(deadline); err != nil {
			return err
		}
		n, err := stream.Read(tmp)
		if err != nil {
			if errors.Is(err, ErrControlSoftReset) {
				nextPush, nextStream, err := runControlLoopRekey(ctx, hooks, "received P_CONTROL_SOFT_RESET_V1")
				if err != nil {
					return err
				}
				if nextStream != nil {
					stream = nextStream
				}
				push = nextPush
				pingInterval = push.PingInterval
				if pingInterval <= 0 && push.PingRestart > 0 {
					pingInterval = push.PingRestart / 2
				}
				pingRestart = push.PingRestart
				renegotiateAt = time.Time{}
				if push.RenegotiateAfter > 0 {
					renegotiateAt = time.Now().Add(push.RenegotiateAfter)
				}
				lastReceived = activity.Last()
				lastPingSent = time.Now()
				buf = nil
				continue
			}
			if errors.Is(err, ErrControlRestart) {
				return err
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("%w: control channel closed", ErrControlRestart)
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("read openvpn control message: %w", err)
		}
		if n == 0 {
			continue
		}
		activity.Mark()
		lastReceived = activity.Last()
		buf = append(buf, tmp[:n]...)
		for {
			idx := bytes.IndexByte(buf, 0)
			if idx < 0 {
				if len(buf) > 64*1024 {
					return errors.New("openvpn control message buffer exceeded 64KiB")
				}
				break
			}
			msg := strings.TrimSpace(string(buf[:idx]))
			buf = buf[idx+1:]
			rekeyReason, err := handleControlMessage(msg, remote)
			if err != nil {
				return err
			}
			if rekeyReason != "" {
				nextPush, nextStream, err := runControlLoopRekey(ctx, hooks, rekeyReason)
				if err != nil {
					return err
				}
				if nextStream != nil {
					stream = nextStream
				}
				push = nextPush
				pingInterval = push.PingInterval
				if pingInterval <= 0 && push.PingRestart > 0 {
					pingInterval = push.PingRestart / 2
				}
				pingRestart = push.PingRestart
				renegotiateAt = time.Time{}
				if push.RenegotiateAfter > 0 {
					renegotiateAt = time.Now().Add(push.RenegotiateAfter)
				}
				lastReceived = activity.Last()
				lastPingSent = time.Now()
				buf = nil
				break
			}
		}
	}
}

func runControlLoopRekey(ctx context.Context, hooks controlLoopHooks, reason string) (*PushReply, controlStream, error) {
	if hooks.rekey == nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrControlRestart, reason)
	}
	nextPush, nextStream, err := hooks.rekey(ctx, reason)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: rekey failed after %s: %v", ErrControlRestart, reason, err)
	}
	if nextPush == nil {
		return nil, nil, fmt.Errorf("%w: rekey returned nil push reply after %s", ErrControlRestart, reason)
	}
	return nextPush, nextStream, nil
}

func nextControlDeadline(now, lastReceived, lastPingSent time.Time, pingInterval, pingRestart time.Duration, renegotiateAt time.Time) time.Time {
	deadline := now.Add(DefaultControlPollDelay)
	if pingInterval > 0 {
		if nextPing := lastPingSent.Add(pingInterval); nextPing.Before(deadline) {
			deadline = nextPing
		}
	}
	if pingRestart > 0 {
		if restart := lastReceived.Add(pingRestart); restart.Before(deadline) {
			deadline = restart
		}
	}
	if !renegotiateAt.IsZero() && renegotiateAt.Before(deadline) {
		deadline = renegotiateAt
	}
	return deadline
}

func writeControlMessage(ctx context.Context, stream controlStream, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := stream.SetWriteDeadline(time.Now().Add(ControlRetransmitDelay)); err != nil {
		return err
	}
	_, err := stream.Write([]byte(message + "\x00"))
	_ = stream.SetWriteDeadline(time.Time{})
	return err
}

func handleControlMessage(message, remote string) (string, error) {
	if message == "" || message == "PING" || strings.HasPrefix(message, "INFO") || strings.HasPrefix(message, "WARNING") || strings.HasPrefix(message, "PUSH_REPLY") {
		return "", nil
	}
	if strings.HasPrefix(message, "AUTH_FAILED") {
		return "", fmt.Errorf("openvpn authentication failed after handshake from %s: %s", remote, message)
	}
	if strings.HasPrefix(message, "RESTART,soft") {
		return message, nil
	}
	if strings.HasPrefix(message, "RESTART") || strings.HasPrefix(message, "HALT") {
		return "", fmt.Errorf("%w: %s", ErrControlRestart, message)
	}
	return "", nil
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.config.CA) {
		return nil, errors.New("parse openvpn ca certificate")
	}
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("openvpn server did not provide certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		return err
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection:   verify,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}
	certPEM := bytes.TrimSpace(c.config.Cert)
	keyPEM := bytes.TrimSpace(c.config.Key)
	if len(certPEM) > 0 && len(keyPEM) > 0 {
		cert, err := tls.X509KeyPair(c.config.Cert, c.config.Key)
		if err != nil {
			return nil, fmt.Errorf("parse client certificate/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

var _ net.Conn = (*ControlConn)(nil)
