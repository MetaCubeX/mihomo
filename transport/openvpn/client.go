package openvpn

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/tls"
	"golang.org/x/sync/semaphore"
)

const (
	ControlRetransmitDelay = time.Second

	// renegotiateTimeout is the maximum time allowed for a TLS renegotiation
	// (rekey) cycle. OpenVPN servers typically rekey every hour; the
	// renegotiation itself should complete in seconds.
	renegotiateTimeout = 30 * time.Second
)

type Client struct {
	config *ClientConfig
	mux    *PacketMux

	control   *ControlChannel
	tlsConn   *tls.Conn
	data      *DataChannel
	dataByKey map[uint8]*DataChannel
	push      *PushReply

	// negotiatedCipher is the data channel cipher selected during the most
	// recent key exchange.
	negotiatedCipher string

	// dataLock protects c.data during TLS renegotiation (rekey), where the
	// DataChannel is atomically replaced.
	dataLock sync.RWMutex
	tlsLock  sync.Mutex
	closed   bool
	authLock sync.RWMutex

	authUsername string
	authPassword string

	// controlReadBuf is owned by Handshake until watchControl starts and by
	// that single watcher afterward. It carries partial TLS control messages.
	controlReadBuf []byte

	errLock sync.Mutex
	runErr  error

	runCtx context.Context
	cancel context.CancelFunc

	writeSem *semaphore.Weighted

	lastSendNano    atomic.Int64
	lastReceiveNano atomic.Int64
}

func NewClient(config *ClientConfig, io PacketIO) (*Client, error) {
	if config == nil {
		return nil, errors.New("nil openvpn client config")
	}
	if io == nil {
		return nil, errors.New("nil openvpn packet io")
	}
	var crypt ControlCryptor
	if len(config.TLSCryptV2Key) > 0 || len(config.TLSCryptV2WrappedKey) > 0 {
		var err error
		crypt, err = NewTLSCryptV2(config.TLSCryptV2Key, config.TLSCryptV2WrappedKey)
		if err != nil {
			return nil, err
		}
	} else if len(config.TLSCryptKey) > 0 {
		var err error
		crypt, err = NewTLSCrypt(config.TLSCryptKey, true)
		if err != nil {
			return nil, err
		}
	} else if len(config.TLSAuthKey) > 0 {
		var err error
		crypt, err = NewTLSAuth(config.TLSAuthKey, config.KeyDirection)
		if err != nil {
			return nil, err
		}
	}
	local, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	mux := NewPacketMux(io)
	go mux.Run(runCtx)
	client := &Client{
		config:       config,
		mux:          mux,
		control:      NewControlChannel(mux, crypt, local),
		dataByKey:    make(map[uint8]*DataChannel, 2),
		runCtx:       runCtx,
		cancel:       cancel,
		writeSem:     semaphore.NewWeighted(1),
		authUsername: strings.TrimSpace(config.Username),
		authPassword: config.Password,
	}
	client.markSend()
	client.markReceive()
	return client, nil
}

func (c *Client) Handshake(ctx context.Context) (*PushReply, error) {
	if c == nil {
		return nil, errors.New("nil openvpn client")
	}
	if err := c.control.SendReset(ctx); err != nil {
		return nil, fmt.Errorf("send hard reset: %w", err)
	}
	if err := c.waitServerReset(ctx); err != nil {
		return nil, err
	}
	stopRetransmit := c.startControlRetransmit(ctx)
	defer stopRetransmit()

	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	controlConn := NewControlConn(c.control)
	tlsConn := tls.Client(controlConn, tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("openvpn tls handshake: %w", err)
	}

	push, err := c.doKeyExchange(ctx, tlsConn, 0, true)
	if err != nil {
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	if !c.setTLSConn(tlsConn) {
		_ = tlsConn.Close()
		return nil, net.ErrClosed
	}
	go c.watchControl()
	return push, nil
}

// doKeyExchange performs the OpenVPN key method 2 exchange over the TLS
// control channel and creates a fresh data channel. It is used both for the
// initial handshake and for subsequent TLS renegotiations (rekeys).
// On success, c.data is atomically replaced with the new DataChannel.
func (c *Client) doKeyExchange(ctx context.Context, tlsConn *tls.Conn, keyID uint8, requestPush bool) (*PushReply, error) {
	primaryCipher := c.config.Cipher
	if len(c.config.DataCiphers) > 0 {
		primaryCipher = normalizeCipher(c.config.DataCiphers[0])
	}

	username, password := c.keyMethodCredentials()
	clientRecord, err := NewClientKeyMethod2Record(
		InstallScriptOptionsString(c.config.Proto, primaryCipher, c.config.Auth, c.config.CompLZO),
		InstallScriptPeerInfo(primaryCipher, c.config.DataCiphers, c.config.CompLZO, c.config.PeerInfo),
		username,
		password,
	)
	if err != nil {
		return nil, err
	}
	clientBytes, err := clientRecord.MarshalClient()
	if err != nil {
		return nil, err
	}
	if _, err := tlsConn.Write(clientBytes); err != nil {
		return nil, fmt.Errorf("write key method 2 client record: %w", err)
	}
	serverRecord, pendingControl, err := c.readServerKeyMethod(ctx, tlsConn)
	if err != nil {
		return nil, err
	}

	// Derive keys using the maximum cipher key length (32 bytes). The actual
	// cipher is determined after the push reply, and keys are sliced to the
	// correct length at that point.
	sources := clientRecord.Sources
	sources.Server = serverRecord.Sources.Server
	keys, err := DeriveClientKeyMaterial(sources, c.control.LocalSessionID(), c.control.RemoteSessionID(), 32)
	if err != nil {
		return nil, fmt.Errorf("derive data channel keys: %w", err)
	}

	push := c.push
	negotiatedCipher := c.negotiatedCipher
	if requestPush {
		if _, err := tlsConn.Write([]byte(PushRequest + "\x00")); err != nil {
			return nil, fmt.Errorf("write push request: %w", err)
		}
		push, pendingControl, err = c.readPushReply(ctx, tlsConn, pendingControl)
		if err != nil {
			return nil, err
		}
		negotiatedCipher, err = c.config.NegotiateCipher(push.DataCiphers, push.Cipher)
		if err != nil {
			return nil, fmt.Errorf("negotiate data cipher: %w", err)
		}
		c.push = push
		c.negotiatedCipher = negotiatedCipher
		c.installPushedAuthToken(push)
	} else if push == nil || negotiatedCipher == "" {
		return nil, errors.New("openvpn rekey started before initial data-channel negotiation")
	}
	if err := c.consumeTLSControlBytes(pendingControl); err != nil {
		return nil, err
	}

	// Slice the derived keys to the negotiated cipher's key length.
	cipherKeyLen := CipherKeyLength(negotiatedCipher)
	keys.SendCipherKey = keys.SendCipherKey[:cipherKeyLen]
	keys.RecvCipherKey = keys.RecvCipherKey[:cipherKeyLen]

	newData, err := newDataChannel(keys, negotiatedCipher, c.config.Auth, push.PeerID, keyID)
	if err != nil {
		return nil, err
	}
	c.installDataChannel(newData)
	c.markSend()
	c.markReceive()
	return push, nil
}

func (c *Client) keyMethodCredentials() (username, password string) {
	c.authLock.RLock()
	defer c.authLock.RUnlock()
	return c.authUsername, c.authPassword
}

func (c *Client) installPushedAuthToken(push *PushReply) bool {
	if push == nil || push.AuthToken == "" {
		return false
	}
	c.authLock.Lock()
	defer c.authLock.Unlock()
	if push.AuthTokenUser != "" {
		c.authUsername = push.AuthTokenUser
	}
	c.authPassword = push.AuthToken
	return true
}

func (c *Client) installDataChannel(newData *DataChannel) {
	c.dataLock.Lock()
	defer c.dataLock.Unlock()

	dataByKey := make(map[uint8]*DataChannel, 2)
	if c.data != nil {
		dataByKey[c.data.keyID] = c.data
	}
	dataByKey[newData.keyID] = newData
	c.data = newData
	c.dataByKey = dataByKey
}

func (c *Client) WriteIPPacket(ctx context.Context, packet []byte) error {
	return c.writeDataPacket(ctx, packet, true)
}

func (c *Client) WritePing(ctx context.Context) error {
	return c.writeDataPacket(ctx, openVPNPingPacket, false)
}

func (c *Client) writeDataPacket(ctx context.Context, packet []byte, compress bool) error {
	if err := c.writeSem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer c.writeSem.Release(1)
	// Acquire the data channel after securing the write semaphore, since a
	// rekey may swap c.data while Acquire is blocked.
	c.dataLock.RLock()
	data := c.data
	c.dataLock.RUnlock()
	if data == nil {
		return errors.New("openvpn data channel is not ready")
	}
	if compress && c.config.CompLZO == CompLzoYes {
		compressed, err := lzo1xCompressSafe(packet)
		if err != nil {
			return err
		}
		packet = compressed
	}
	encrypted, err := data.Encrypt(packet)
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
	for {
		packet, err := c.mux.ReadDataPacket(ctx)
		if err != nil {
			return nil, err
		}
		// Re-acquire the data channel after reading, since a rekey may have
		// swapped c.data while ReadDataPacket was blocked.
		_, keyID := parseOpcodeKeyID(packet[0])
		c.dataLock.RLock()
		data := c.dataByKey[keyID]
		c.dataLock.RUnlock()
		if data == nil {
			continue
		}
		plain, err := data.Decrypt(packet)
		if err != nil {
			continue
		}
		c.markReceive()
		if IsPingPacket(plain) {
			continue
		}
		if c.config.CompLZO == CompLzoYes && len(plain) > 0 {
			return lzo1xDecompressSafe(plain)
		}
		return plain, nil
	}
}

// watchControl monitors the control channel for TLS renegotiation requests
// (soft resets / rekeys). When the server initiates a rekey, the client
// performs a full TLS renegotiation followed by a new key method 2 exchange,
// then atomically swaps in a fresh DataChannel. If renegotiation fails or
// the control channel stops, the client is terminated.
func (c *Client) watchControl() {
	readBuffer := make([]byte, 4096)
	for {
		tlsConn := c.currentTLSConn()
		if tlsConn == nil {
			if c.runCtx.Err() == nil {
				c.fail(errors.New("watch OpenVPN control channel: missing TLS connection"))
			}
			return
		}

		n, err := tlsConn.Read(readBuffer)
		if n > 0 {
			if controlErr := c.consumeTLSControlBytes(readBuffer[:n]); controlErr != nil {
				c.fail(controlErr)
				return
			}
		}
		if err == nil {
			continue
		}

		var resetErr *softResetReadError
		if errors.As(err, &resetErr) {
			c.controlReadBuf = nil
			if err := c.renegotiate(resetErr.packet); err != nil {
				if c.runCtx.Err() == nil {
					c.fail(err)
				}
				return
			}
			continue
		}
		if c.runCtx.Err() == nil {
			c.fail(fmt.Errorf("watch OpenVPN TLS control channel: %w", err))
		}
		return
	}
}

func (c *Client) currentTLSConn() *tls.Conn {
	c.tlsLock.Lock()
	defer c.tlsLock.Unlock()
	return c.tlsConn
}

func (c *Client) consumeTLSControlBytes(data []byte) error {
	c.controlReadBuf = append(c.controlReadBuf, data...)
	for {
		end := bytes.IndexByte(c.controlReadBuf, 0)
		if end < 0 {
			if len(c.controlReadBuf) > 64*1024 {
				return errors.New("OpenVPN TLS control message exceeds 64 KiB")
			}
			return nil
		}
		message := string(c.controlReadBuf[:end])
		c.controlReadBuf = c.controlReadBuf[end+1:]
		if err := c.handleTLSControlMessage(message); err != nil {
			return err
		}
	}
}

func (c *Client) handleTLSControlMessage(message string) error {
	message = strings.TrimSpace(message)
	switch {
	case strings.HasPrefix(message, "PUSH_REPLY"):
		push, err := parsePushReply(message, false)
		if err != nil {
			return fmt.Errorf("parse OpenVPN control push: %w", err)
		}
		c.installPushedAuthToken(push)
		return nil
	case strings.HasPrefix(message, "AUTH_FAILED"):
		return errors.New("OpenVPN server rejected authentication")
	default:
		return nil
	}
}

// renegotiate performs a single OpenVPN key-epoch transition:
// 1. Send our own soft reset to acknowledge the server's rekey request
// 2. Create and handshake a fresh TLS session for the new key epoch
// 3. Exchange fresh key method 2 records and derive new data channel keys
// 4. Atomically replace c.data with the new DataChannel
func (c *Client) renegotiate(reset *ControlPacket) error {
	renegCtx, cancel := context.WithTimeout(c.runCtx, renegotiateTimeout)
	defer cancel()
	stopRetransmit := c.startControlRetransmit(renegCtx)
	defer stopRetransmit()

	if err := c.control.respondSoftReset(renegCtx, reset); err != nil {
		return fmt.Errorf("respond to OpenVPN soft reset: %w", err)
	}

	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return fmt.Errorf("configure OpenVPN rekey TLS session: %w", err)
	}
	tlsConn := tls.Client(NewControlConn(c.control), tlsConfig)
	if deadline, ok := renegCtx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(renegCtx); err != nil {
		return fmt.Errorf("handshake OpenVPN rekey TLS session: %w", err)
	}

	if _, err := c.doKeyExchange(renegCtx, tlsConn, reset.KeyID, false); err != nil {
		return fmt.Errorf("exchange OpenVPN rekey material: %w", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	if !c.setTLSConn(tlsConn) {
		_ = tlsConn.Close()
		return net.ErrClosed
	}
	return nil
}

func (c *Client) startControlRetransmit(ctx context.Context) func() {
	if c.config.Proto != ProtoUDP {
		return func() {}
	}
	retransmitCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(ControlRetransmitDelay)
		defer ticker.Stop()
		for {
			select {
			case <-retransmitCtx.Done():
				return
			case <-ticker.C:
				writeCtx, cancelWrite := context.WithTimeout(retransmitCtx, ControlRetransmitDelay)
				_ = c.control.RetransmitPending(writeCtx)
				cancelWrite()
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func (c *Client) setTLSConn(tlsConn *tls.Conn) bool {
	c.tlsLock.Lock()
	defer c.tlsLock.Unlock()
	if c.closed {
		return false
	}
	c.tlsConn = tlsConn
	return true
}

func (c *Client) fail(err error) {
	c.tlsLock.Lock()
	if c.closed {
		c.tlsLock.Unlock()
		return
	}
	c.errLock.Lock()
	if c.runErr == nil {
		c.runErr = err
	}
	c.errLock.Unlock()
	c.tlsLock.Unlock()
	c.cancel()
	_ = c.mux.Close()
}

func (c *Client) Err() error {
	c.errLock.Lock()
	defer c.errLock.Unlock()
	return c.runErr
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
	c.tlsLock.Lock()
	c.closed = true
	tlsConn := c.tlsConn
	c.tlsConn = nil
	c.tlsLock.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	if tlsConn != nil {
		_ = tlsConn.Close()
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

func (c *Client) readServerKeyMethod(ctx context.Context, tlsConn *tls.Conn) (*KeyMethod2Record, []byte, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = tlsConn.SetReadDeadline(deadline)
		}
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return nil, nil, fmt.Errorf("read key method 2 server record: %w", err)
		}
		buf = append(buf, tmp[:n]...)
		recordLength, complete, err := serverKeyMethod2RecordLength(buf)
		if err != nil {
			return nil, nil, err
		}
		if complete {
			record, err := ParseServerKeyMethod2Record(buf[:recordLength])
			if err != nil {
				return nil, nil, err
			}
			return record, cloneBytes(buf[recordLength:]), nil
		}
	}
}

func (c *Client) readPushReply(ctx context.Context, tlsConn *tls.Conn, pending []byte) (*PushReply, []byte, error) {
	message, remaining, err := readTLSControlMessage(ctx, tlsConn, pending)
	if err != nil {
		return nil, nil, fmt.Errorf("read push reply: %w", err)
	}
	push, err := ParsePushReply(message)
	if err != nil {
		return nil, nil, err
	}
	return push, remaining, nil
}

func readTLSControlMessage(ctx context.Context, tlsConn *tls.Conn, pending []byte) (string, []byte, error) {
	buf := cloneBytes(pending)
	tmp := make([]byte, 4096)
	for {
		if end := bytes.IndexByte(buf, 0); end >= 0 {
			return string(buf[:end]), cloneBytes(buf[end+1:]), nil
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = tlsConn.SetReadDeadline(deadline)
		}
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return "", nil, err
		}
		buf = append(buf, tmp[:n]...)
	}
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
