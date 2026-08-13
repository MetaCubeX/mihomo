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

	control *ControlChannel
	tlsConn *tls.Conn
	data    *DataChannel
	// retiring is the previous data-channel epoch, kept during a rekey so
	// packets still labeled with the old key ID can be decrypted.
	retiring *DataChannel
	push     *PushReply
	authUser string
	authPass string
	// leftoverTLS is unread TLS control bytes after a key-method-2 record.
	leftoverTLS []byte
	// lastRekeyErr is the original renegotiation failure, preserved because
	// closing the mux otherwise only surfaces "use of closed network connection".
	lastRekeyErr error
	rekeyLogOnce sync.Once
	// dataByKey keeps active and retiring data channels indexed by key ID.
	dataByKey map[uint8]*DataChannel
	// lastSoftResetKey is the key ID from the most recently accepted server
	// soft-reset packet. Tests inspect this after a rekey.
	lastSoftResetKey uint8
	// lastDataKey is the key ID encoded on the current outgoing data header.
	lastDataKey uint8
	// lastAuthToken is the most recently pushed auth-token, if any.
	lastAuthToken string
	// tlsEpoch is incremented every time a new tls.Conn is installed.
	tlsEpoch uint32
	// controlConn is the net.Conn adapter wrapping the control channel.
	controlConn *ControlConn

	// negotiatedCipher is the data channel cipher selected during the most
	// recent key exchange.
	negotiatedCipher string

	// dataLock protects c.data during TLS renegotiation (rekey), where the
	// DataChannel is atomically replaced.
	dataLock sync.RWMutex

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
		config:    config,
		mux:       mux,
		control:   NewControlChannel(mux, crypt, local),
		runCtx:    runCtx,
		cancel:    cancel,
		writeSem:  semaphore.NewWeighted(1),
		authUser:  strings.TrimSpace(config.Username),
		authPass:  config.Password,
		dataByKey: make(map[uint8]*DataChannel),
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

	if err := c.startTLSEpoch(ctx); err != nil {
		return nil, err
	}

	push, err := c.doKeyExchange(ctx)
	if err != nil {
		return nil, err
	}
	_ = c.tlsConn.SetDeadline(time.Time{})
	go c.watchControl()
	return push, nil
}

func (c *Client) startTLSEpoch(ctx context.Context) error {
	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return err
	}
	if c.controlConn == nil {
		c.controlConn = NewControlConn(c.control)
	}
	if c.tlsConn != nil {
		// Drop the old epoch without writing close_notify. Close() would send
		// it on whatever key ID is current and pollute the new control epoch.
		c.tlsConn = nil
	}
	c.controlConn.Reset()
	c.leftoverTLS = nil
	c.tlsConn = tls.Client(c.controlConn, tlsConfig)
	c.tlsEpoch++
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.tlsConn.SetDeadline(deadline)
	}
	if err := c.tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("openvpn tls handshake: %w", err)
	}
	return nil
}

// doKeyExchange performs the OpenVPN key method 2 exchange over the TLS
// control channel and creates a fresh data channel. It is used both for the
// initial handshake and for subsequent TLS renegotiations (rekeys).
// On success, c.data is atomically replaced with the new DataChannel.
func (c *Client) doKeyExchange(ctx context.Context) (*PushReply, error) {
	primaryCipher := c.config.Cipher
	if len(c.config.DataCiphers) > 0 {
		primaryCipher = normalizeCipher(c.config.DataCiphers[0])
	}

	clientRecord, err := NewClientKeyMethod2Record(
		InstallScriptOptionsString(c.config.Proto, primaryCipher, c.config.Auth, c.config.CompLZO),
		InstallScriptPeerInfo(primaryCipher, c.config.DataCiphers, c.config.CompLZO, c.config.PeerInfo),
		c.authUser,
		c.authPass,
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
	serverRecord, err := c.readServerKeyMethod(ctx)
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

	if c.push != nil {
		// Authenticated rekeys keep the previous ifconfig / peer-id.
		// OpenVPN 2.6 often does not send another PUSH_REPLY here.
		push := mergePushReply(c.push, &PushReply{})
		c.push = push
		negotiatedCipher, err := c.config.NegotiateCipher(push.DataCiphers, push.Cipher)
		if err != nil {
			return nil, fmt.Errorf("negotiate data cipher: %w", err)
		}
		c.negotiatedCipher = negotiatedCipher
		cipherKeyLen := CipherKeyLength(negotiatedCipher)
		keys.SendCipherKey = keys.SendCipherKey[:cipherKeyLen]
		keys.RecvCipherKey = keys.RecvCipherKey[:cipherKeyLen]
		keyID := c.control.KeyID()
		newData, err := NewDataChannel(keys, negotiatedCipher, c.config.Auth, push.PeerID, keyID)
		if err != nil {
			return nil, err
		}
		c.installDataChannel(newData)
		c.markSend()
		c.markReceive()
		return push, nil
	}

	if _, err := c.tlsConn.Write([]byte(PushRequest + "\x00")); err != nil {
		return nil, fmt.Errorf("write push request: %w", err)
	}
	push, err := c.readPushReply(ctx)
	if err != nil {
		return nil, err
	}
	push = mergePushReply(c.push, push)
	if len(push.Prefixes) == 0 {
		return nil, fmt.Errorf("openvpn push reply missing ifconfig address")
	}
	c.push = push

	// Negotiate the data channel cipher based on the push reply.
	negotiatedCipher, err := c.config.NegotiateCipher(push.DataCiphers, push.Cipher)
	if err != nil {
		return nil, fmt.Errorf("negotiate data cipher: %w", err)
	}
	c.negotiatedCipher = negotiatedCipher

	// Slice the derived keys to the negotiated cipher's key length.
	cipherKeyLen := CipherKeyLength(negotiatedCipher)
	keys.SendCipherKey = keys.SendCipherKey[:cipherKeyLen]
	keys.RecvCipherKey = keys.RecvCipherKey[:cipherKeyLen]

	keyID := c.control.KeyID()
	newData, err := NewDataChannel(keys, negotiatedCipher, c.config.Auth, push.PeerID, keyID)
	if err != nil {
		return nil, err
	}
	c.installDataChannel(newData)
	c.captureAuthToken(push)
	c.markSend()
	c.markReceive()
	return push, nil
}

func (c *Client) installDataChannel(newData *DataChannel) {
	c.dataLock.Lock()
	old := c.data
	c.retiring = old
	c.data = newData
	c.lastDataKey = newData.keyID
	if c.dataByKey == nil {
		c.dataByKey = make(map[uint8]*DataChannel)
	}
	if old != nil && old.keyID != newData.keyID {
		c.dataByKey[old.keyID] = old
	}
	c.dataByKey[newData.keyID] = newData
	// Keep at most the current and previous epoch.
	for id := range c.dataByKey {
		if id != newData.keyID && (old == nil || id != old.keyID) {
			delete(c.dataByKey, id)
		}
	}
	c.dataLock.Unlock()
}

func (c *Client) captureAuthToken(push *PushReply) {
	if push == nil {
		return
	}
	user, pass, ok := push.AuthToken()
	if !ok {
		return
	}
	c.lastAuthToken = pass
	if user != "" {
		c.authUser = user
	}
	c.authPass = pass
}

func (c *Client) ActiveDataKeyID() uint8 {
	c.dataLock.RLock()
	defer c.dataLock.RUnlock()
	if c.data == nil {
		return 0
	}
	return c.data.keyID
}

func (c *Client) LastSoftResetKeyID() uint8 {
	c.dataLock.RLock()
	defer c.dataLock.RUnlock()
	return c.lastSoftResetKey
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

func (c *Client) LastRekeyError() error {
	return c.lastRekeyErr
}

func (c *Client) ReadIPPacket(ctx context.Context) ([]byte, error) {
	for {
		packet, err := c.mux.ReadDataPacket(ctx)
		if err != nil {
			if c.lastRekeyErr != nil {
				return nil, fmt.Errorf("%w: %v", err, c.lastRekeyErr)
			}
			return nil, err
		}
		plain, err := c.decryptDataPacket(packet)
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

func (c *Client) decryptDataPacket(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, errors.New("empty openvpn data packet")
	}
	_, keyID := parseOpcodeKeyID(packet[0])
	c.dataLock.RLock()
	data := c.data
	if alt, ok := c.dataByKey[keyID]; ok {
		data = alt
	} else if c.retiring != nil && c.retiring.keyID == keyID {
		data = c.retiring
	}
	c.dataLock.RUnlock()
	if data == nil {
		return nil, errors.New("openvpn data channel is not ready")
	}
	return data.Decrypt(packet)
}

// watchControl monitors the control channel for TLS renegotiation requests
// (soft resets / rekeys). When the server initiates a rekey, the client
// performs a full TLS renegotiation followed by a new key method 2 exchange,
// then atomically swaps in a fresh DataChannel. If renegotiation fails or
// the control channel stops, the client is terminated.
func (c *Client) watchControl() {
	for {
		packet, err := c.control.waitForSoftReset(c.runCtx)
		if err != nil {
			c.failControl(fmt.Errorf("wait for soft reset: %w", err))
			return
		}
		if err := c.renegotiate(packet); err != nil {
			c.failControl(fmt.Errorf("renegotiate: %w", err))
			return
		}
	}
}

func (c *Client) failControl(err error) {
	c.lastRekeyErr = err
	c.rekeyLogOnce.Do(func() {
		// Keep the original rekey error; the packet reader otherwise only
		// sees the secondary "use of closed network connection".
		_ = err
	})
	c.cancel()
	_ = c.mux.Close()
}

// errRenegotiateNoTLS is returned when renegotiate() is called before a TLS
// connection has been established.
var errRenegotiateNoTLS = errors.New("cannot renegotiate: tls connection not established")

// renegotiate performs a single TLS renegotiation cycle:
// 1. Send our own soft reset to acknowledge the server's rekey request
// 2. Renegotiate the TLS session on the existing tlsConn
// 3. Exchange fresh key method 2 records and derive new data channel keys
// 4. Atomically replace c.data with the new DataChannel
func (c *Client) renegotiate(serverReset *ControlPacket) error {
	if c.tlsConn == nil && c.controlConn == nil {
		return errRenegotiateNoTLS
	}
	renegCtx, cancel := context.WithTimeout(c.runCtx, renegotiateTimeout)
	defer cancel()

	keyID := NextKeyID(c.control.KeyID())
	if serverReset != nil {
		keyID = serverReset.KeyID & KeyIDMask
	}
	c.dataLock.Lock()
	c.lastSoftResetKey = keyID
	c.dataLock.Unlock()
	// Adopt first so QueueAck lands on the new epoch; AdoptKeyID clears acks.
	c.control.AdoptKeyID(keyID)
	if serverReset != nil {
		// The watcher already consumed the server soft reset (new-epoch
		// message 0). Advance recvMessage or ControlConn.Read will park
		// ServerHello in recvPending forever.
		c.control.MarkReceived(serverReset.MessageID)
		c.control.QueueAck(serverReset.MessageID)
	}

	if err := c.control.SendSoftReset(renegCtx); err != nil {
		return fmt.Errorf("send soft reset: %w", err)
	}

	if err := c.startTLSEpoch(renegCtx); err != nil {
		return fmt.Errorf("tls epoch handshake: %w", err)
	}

	if _, err := c.doKeyExchange(renegCtx); err != nil {
		return fmt.Errorf("rekey exchange: %w", err)
	}
	return nil
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
	buf := append([]byte(nil), c.leftoverTLS...)
	c.leftoverTLS = nil
	tmp := make([]byte, 4096)
	for {
		if len(buf) > 0 {
			record, consumed, err := ParseServerKeyMethod2RecordConsumed(buf)
			if err == nil {
				c.leftoverTLS = append([]byte(nil), buf[consumed:]...)
				return record, nil
			}
			if !strings.Contains(err.Error(), "truncated") && !errors.Is(err, ioStringEOF) {
				return nil, err
			}
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.tlsConn.SetReadDeadline(deadline)
		}
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			return nil, fmt.Errorf("read key method 2 server record: %w", err)
		}
		buf = append(buf, tmp[:n]...)
	}
}

func (c *Client) readPushReply(ctx context.Context) (*PushReply, error) {
	buf := append([]byte(nil), c.leftoverTLS...)
	c.leftoverTLS = nil
	tmp := make([]byte, 4096)
	for {
		if bytes.Contains(buf, []byte("AUTH_FAILED")) {
			msg := string(buf)
			if idx := strings.IndexByte(msg, 0); idx >= 0 {
				msg = msg[:idx]
			}
			return nil, fmt.Errorf("openvpn authentication failed: %s", strings.TrimSpace(msg))
		}
		if reply, rest, ok := takePushReply(buf); ok {
			c.leftoverTLS = rest
			return reply, nil
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.tlsConn.SetReadDeadline(deadline)
		}
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				if reply, _, parseErr := ParsePushReplyFlexible(string(buf)); parseErr == nil {
					return reply, nil
				}
			}
			return nil, fmt.Errorf("read push reply: %w", err)
		}
		buf = append(buf, tmp[:n]...)
	}
}

func takePushReply(buf []byte) (*PushReply, []byte, bool) {
	if len(buf) == 0 {
		return nil, nil, false
	}
	// AUTH_FAILED may arrive instead of PUSH_REPLY.
	if bytes.Contains(buf, []byte("AUTH_FAILED")) {
		msg := string(buf)
		if idx := strings.IndexByte(msg, 0); idx >= 0 {
			msg = msg[:idx]
		}
		return nil, nil, false
	}
	if !bytes.Contains(buf, []byte("PUSH_REPLY")) {
		return nil, nil, false
	}
	msg := string(buf)
	rest := []byte(nil)
	if idx := strings.IndexByte(msg, 0); idx >= 0 {
		rest = append([]byte(nil), buf[idx+1:]...)
		msg = msg[:idx]
	} else if !bytes.Contains(buf, []byte("ifconfig")) {
		return nil, nil, false
	}
	reply, err := parsePushReplyInner(msg)
	if err != nil {
		return nil, nil, false
	}
	return reply, rest, true
}

func mergePushReply(prev, next *PushReply) *PushReply {
	if next == nil {
		return prev
	}
	if prev == nil {
		return next
	}
	if len(next.Prefixes) == 0 {
		next.Prefixes = prev.Prefixes
	}
	if len(next.Routes) == 0 {
		next.Routes = prev.Routes
	}
	if next.PeerID == PeerIDUnset {
		next.PeerID = prev.PeerID
	}
	if next.Cipher == "" {
		next.Cipher = prev.Cipher
	}
	if len(next.DataCiphers) == 0 {
		next.DataCiphers = prev.DataCiphers
	}
	if next.AuthTokenPass == "" {
		next.AuthTokenPass = prev.AuthTokenPass
		if next.AuthTokenUser == "" {
			next.AuthTokenUser = prev.AuthTokenUser
		}
	}
	return next
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
		// Allow the server to initiate TLS renegotiation (rekey). OpenVPN
		// servers rekey the control channel at regular intervals (default 1h).
		Renegotiation: tls.RenegotiateFreelyAsClient,
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
