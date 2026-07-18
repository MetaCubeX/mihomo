package openvpn

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
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
	push    *PushReply

	// negotiatedCipher is the data channel cipher selected during the most
	// recent key exchange. It is determined by intersecting the client's
	// DataCiphers list with the server's pushed cipher list.
	negotiatedCipher string

	// compressor handles data channel compression framing.
	compressor *Compressor
	// fragmenter handles OpenVPN fragment v1 framing and bounded reassembly.
	fragmenter *Fragmenter

	// dataLock protects c.data during TLS renegotiation (rekey), where the
	// DataChannel is atomically replaced. Read and write paths acquire a
	// read lock before touching c.data.
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
		config:     config,
		mux:        mux,
		control:    NewControlChannel(mux, crypt, local),
		runCtx:     runCtx,
		cancel:     cancel,
		writeSem:   semaphore.NewWeighted(1),
		compressor: config.buildCompressor(),
	}
	if config.Fragment > 0 {
		client.fragmenter = NewFragmenter()
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

	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	controlConn := NewControlConn(c.control)
	c.tlsConn = tls.Client(controlConn, tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.tlsConn.SetDeadline(deadline)
	}
	if err := c.tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("openvpn tls handshake: %w", err)
	}

	push, err := c.doKeyExchange(ctx)
	if err != nil {
		return nil, err
	}
	_ = c.tlsConn.SetDeadline(time.Time{})
	go c.watchControl()
	return push, nil
}

// doKeyExchange performs the OpenVPN key method 2 exchange over the TLS
// control channel and creates a fresh data channel. It is used both for the
// initial handshake and for subsequent TLS renegotiations (rekeys).
// On success, c.data is atomically replaced with the new DataChannel.
func (c *Client) doKeyExchange(ctx context.Context) (*PushReply, error) {
	// Determine the cipher for the options string. If DataCiphers is
	// configured, the first entry is advertised as the primary cipher.
	// The actual negotiated cipher is resolved after receiving the push reply.
	primaryCipher := c.config.Cipher
	if len(c.config.DataCiphers) > 0 {
		primaryCipher = normalizeCipher(c.config.DataCiphers[0])
	}

	clientRecord, err := NewClientKeyMethod2Record(
		InstallScriptOptionsString(c.config.Proto, primaryCipher, c.config.Auth, c.config.CompLZO),
		InstallScriptPeerInfo(primaryCipher, c.config.DataCiphers, c.config.CompLZO, c.config.Compression, c.config.PeerInfo),
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
	serverRecord, err := c.readServerKeyMethod(ctx)
	if err != nil {
		return nil, err
	}

	// Derive keys using the maximum cipher key length (32 bytes). The actual
	// cipher is determined after the push reply, and keys are sliced to the
	// correct length at that point. This works because OpenVPN's key
	// expansion always produces a full key block of 2*(64+64) bytes, and each
	// cipher only uses the first N bytes of its 64-byte slot.
	sources := clientRecord.Sources
	sources.Server = serverRecord.Sources.Server
	keys, err := DeriveClientKeyMaterial(sources, c.control.LocalSessionID(), c.control.RemoteSessionID(), 32)
	if err != nil {
		return nil, fmt.Errorf("derive data channel keys: %w", err)
	}

	if _, err := c.tlsConn.Write([]byte(PushRequest + "\x00")); err != nil {
		return nil, fmt.Errorf("write push request: %w", err)
	}
	push, err := c.readPushReply(ctx)
	if err != nil {
		return nil, err
	}
	c.push = push

	// Apply pull filters to the push reply.
	if err := push.ApplyPullFilters(c.config.PullFilters); err != nil {
		return nil, fmt.Errorf("apply pull filters: %w", err)
	}

	// Apply route-no-pull if configured.
	push.ApplyRouteNoPull(c.config.RouteNoPull)

	// Merge locally configured routes.
	push.MergeLocalRoutes(c.config.Routes)

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

	newData, err := NewDataChannel(keys, negotiatedCipher, c.config.Auth, push.PeerID)
	if err != nil {
		return nil, err
	}
	c.dataLock.Lock()
	oldData := c.data
	c.data = newData
	c.dataLock.Unlock()
	// oldData is simply dropped; the GC will reclaim it once in-flight
	// read/write operations that captured the old pointer finish.
	_ = oldData
	c.markSend()
	c.markReceive()
	return push, nil
}

func (c *Client) WriteIPPacket(ctx context.Context, packet []byte) error {
	return c.writeDataPacket(ctx, packet, true)
}

func (c *Client) WritePing(ctx context.Context) error {
	return c.writeDataPacket(ctx, openVPNPingPacket, false)
}

func (c *Client) writeDataPacket(ctx context.Context, packet []byte, frameIP bool) error {
	c.dataLock.RLock()
	data := c.data
	c.dataLock.RUnlock()
	if data == nil {
		return errors.New("openvpn data channel is not ready")
	}
	if err := c.writeSem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer c.writeSem.Release(1)

	if frameIP && c.config.MSSFix > 0 {
		fixed := ipv4MinHeader + tcpMinHeader
		if c.compressor != nil {
			fixed += c.compressor.PayloadOverhead()
		}
		if c.fragmenter != nil {
			fixed += 4
		}
		maximum, err := data.MaxPayloadForPacketSize(int(c.config.MSSFix), fixed)
		if err != nil {
			return fmt.Errorf("calculate mss-fix: %w", err)
		}
		if maximum > 0xffff {
			maximum = 0xffff
		}
		packet = clampTCPSegmentMSS(packet, uint16(maximum))
	}

	if frameIP {
		if c.compressor != nil {
			framed, err := c.compressor.CompressFrame(packet)
			if err != nil {
				return err
			}
			packet = framed
		} else if c.config.CompLZO == CompLzoYes {
			framed, err := lzo1xCompressSafe(packet)
			if err != nil {
				return err
			}
			packet = framed
		}
	}

	payloads := [][]byte{packet}
	if frameIP && c.fragmenter != nil {
		fragmentSize, err := data.MaxPayloadForPacketSize(int(c.config.Fragment), 4)
		if err != nil {
			return fmt.Errorf("calculate fragment size: %w", err)
		}
		payloads, err = c.fragmenter.Encode(packet, fragmentSize)
		if err != nil {
			return err
		}
	}
	for _, payload := range payloads {
		encrypted, err := data.Encrypt(payload)
		if err != nil {
			return err
		}
		if err = c.mux.WritePacket(ctx, encrypted); err != nil {
			return err
		}
	}
	c.markSend()
	return nil
}

func (c *Client) ReadIPPacket(ctx context.Context) ([]byte, error) {
	for {
		c.dataLock.RLock()
		data := c.data
		c.dataLock.RUnlock()
		if data == nil {
			return nil, errors.New("openvpn data channel is not ready")
		}
		packet, err := c.mux.ReadDataPacket(ctx)
		if err != nil {
			return nil, err
		}
		plain, err := data.Decrypt(packet)
		if err != nil {
			continue
		}
		c.markReceive()
		if IsPingPacket(plain) {
			continue
		}

		if c.fragmenter != nil {
			reassembled, complete, err := c.fragmenter.Decode(plain)
			if err != nil || !complete {
				continue
			}
			plain = reassembled
		}

		// Remove compression framing if configured.
		if c.compressor != nil {
			decompressed, err := c.compressor.DecompressFrame(plain)
			if err != nil {
				continue
			}
			plain = decompressed
		} else if c.config.CompLZO == CompLzoYes && len(plain) > 0 {
			// Legacy comp-lzo path (no compress directive).
			decompressed, err := lzo1xDecompressSafe(plain)
			if err != nil {
				continue
			}
			plain = decompressed
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
	for {
		err := c.control.waitForSoftReset(c.runCtx)
		if err != nil {
			c.cancel()
			_ = c.mux.Close()
			return
		}
		// Server initiated a rekey. Perform renegotiation.
		if err := c.renegotiate(); err != nil {
			c.cancel()
			_ = c.mux.Close()
			return
		}
	}
}

// errRenegotiateNoTLS is returned when renegotiate() is called before a TLS
// connection has been established (e.g. in unit tests without a real server).
var errRenegotiateNoTLS = errors.New("cannot renegotiate: tls connection not established")

// renegotiate performs a single TLS renegotiation cycle:
// 1. Send our own soft reset to acknowledge the server's rekey request
// 2. Renegotiate the TLS session on the existing tlsConn
// 3. Exchange fresh key method 2 records and derive new data channel keys
// 4. Atomically replace c.data with the new DataChannel
func (c *Client) renegotiate() error {
	if c.tlsConn == nil {
		return errRenegotiateNoTLS
	}
	renegCtx, cancel := context.WithTimeout(c.runCtx, renegotiateTimeout)
	defer cancel()

	// Acknowledge the server's soft reset by sending our own.
	if err := c.control.SendSoftReset(renegCtx); err != nil {
		return fmt.Errorf("send soft reset: %w", err)
	}

	// Perform TLS renegotiation. The tlsConn was configured with
	// RenegotiateFreelyAsClient, so this re-enters the TLS handshake on
	// the existing connection.
	if err := c.tlsConn.HandshakeContext(renegCtx); err != nil {
		return fmt.Errorf("tls renegotiation: %w", err)
	}

	// Exchange fresh key material and swap the data channel.
	_, err := c.doKeyExchange(renegCtx)
	if err != nil {
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

// ExplicitExitNotifyCount is the default number of EXIT notifications sent.
const ExplicitExitNotifyCount = 1

func (c *Client) Close() error {
	// Send explicit exit notify if configured (UDP only).
	if c.config.ExplicitExitNotify > 0 && c.config.Proto == ProtoUDP && c.tlsConn != nil {
		c.sendExitNotify(int(c.config.ExplicitExitNotify))
	}
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

// sendExitNotify sends N EXIT control messages over the TLS control channel.
// This tells the server to immediately close the session rather than waiting
// for a keepalive timeout. Only effective on UDP transport.
func (c *Client) sendExitNotify(count int) {
	if count > 10 {
		count = 10
	}
	if count < 1 {
		count = 1
	}
	exitPayload := append([]byte("EXIT"), 0)
	for i := 0; i < count; i++ {
		_ = c.tlsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.tlsConn.Write(exitPayload); err != nil {
			break
		}
	}
	_ = c.tlsConn.SetWriteDeadline(time.Time{})
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
	tmp := make([]byte, 4096)
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.tlsConn.SetReadDeadline(deadline)
		}
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				break
			}
			return nil, fmt.Errorf("read push reply: %w", err)
		}
		buf = append(buf, tmp[:n]...)
		if bytes.Contains(buf, []byte("\x00")) || strings.Contains(string(buf), "PUSH_REPLY") {
			msg := string(buf)
			if idx := strings.IndexByte(msg, 0); idx >= 0 {
				msg = msg[:idx]
			}
			if reply, err := ParsePushReply(msg); err == nil {
				return reply, nil
			}
		}
	}
	return nil, ctx.Err()
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.config.CA) {
		return nil, errors.New("parse openvpn ca certificate")
	}

	// Parse peer fingerprints (if any).
	var fingerprints [][]byte
	for _, fp := range c.config.PeerFingerprint {
		fp = strings.TrimSpace(strings.ToLower(fp))
		if len(fp) != 64 {
			return nil, fmt.Errorf("invalid peer fingerprint length %d, expected 64 hex chars", len(fp))
		}
		b, err := hex.DecodeString(fp)
		if err != nil {
			return nil, fmt.Errorf("invalid peer fingerprint %q: %w", fp, err)
		}
		fingerprints = append(fingerprints, b)
	}

	// Parse remote-cert-ku (hex key usage masks).
	var requiredKUMasks []uint16
	for _, ku := range c.config.RemoteCertKU {
		ku = strings.TrimSpace(ku)
		v, err := strconv.ParseUint(ku, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid remote-cert-ku %q: %w", ku, err)
		}
		requiredKUMasks = append(requiredKUMasks, uint16(v))
	}

	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("openvpn server did not provide certificate")
		}
		leaf := cs.PeerCertificates[0]

		// Peer fingerprint verification (if configured).
		if len(fingerprints) > 0 {
			leafHash := sha256.Sum256(leaf.Raw)
			matched := false
			for _, fp := range fingerprints {
				if hmac.Equal(leafHash[:], fp) {
					matched = true
					break
				}
			}
			if !matched {
				return errors.New("openvpn server certificate fingerprint does not match")
			}
		}

		// Certificate chain verification (if CA is configured).
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		verifyOpts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		_, err := leaf.Verify(verifyOpts)
		if err != nil && len(fingerprints) == 0 {
			// If no fingerprint match, chain verification failure is fatal.
			return err
		}

		// Server name verification (if configured).
		if c.config.ServerName != "" {
			if err := verifyServerName(leaf, c.config.ServerName, c.config.ServerNameType); err != nil {
				return err
			}
		}

		// Remote cert KU verification (if configured).
		if len(requiredKUMasks) > 0 {
			if err := verifyKeyUsage(leaf, requiredKUMasks); err != nil {
				return err
			}
		}

		// Remote cert EKU verification (if configured).
		if c.config.RemoteCertEKU != "" {
			if err := verifyEKU(leaf, c.config.RemoteCertEKU); err != nil {
				return err
			}
		}

		return nil
	}

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection:   verify,
		Renegotiation:      tls.RenegotiateFreelyAsClient,
	}

	// TLS version limits.
	if v, err := parseTLSVersion(c.config.TLSVersionMin); err == nil && v != 0 {
		cfg.MinVersion = v
	} else if err != nil {
		return nil, err
	}
	if v, err := parseTLSVersion(c.config.TLSVersionMax); err == nil && v != 0 {
		cfg.MaxVersion = v
	} else if err != nil {
		return nil, err
	}

	// Client certificate (if configured).
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

// verifyServerName checks the server certificate against the expected name.
func verifyServerName(cert *x509.Certificate, name, nameType string) error {
	nameType = strings.ToLower(strings.TrimSpace(nameType))
	if nameType == "" {
		nameType = "name"
	}
	switch nameType {
	case "subject":
		if cert.Subject.String() != name {
			return fmt.Errorf("openvpn certificate subject mismatch: expected %q, got %q", name, cert.Subject.String())
		}
	case "name":
		// Check CN and SANs.
		if cert.Subject.CommonName == name {
			return nil
		}
		for _, san := range cert.DNSNames {
			if san == name {
				return nil
			}
		}
		return fmt.Errorf("openvpn certificate name mismatch: %q not found in CN or SANs", name)
	case "name-prefix":
		if strings.HasPrefix(cert.Subject.CommonName, name) {
			return nil
		}
		for _, san := range cert.DNSNames {
			if strings.HasPrefix(san, name) {
				return nil
			}
		}
		return fmt.Errorf("openvpn certificate name-prefix mismatch: no CN/SAN starts with %q", name)
	default:
		return fmt.Errorf("unsupported server_name_type %q", nameType)
	}
	return nil
}

// verifyKeyUsage checks that the certificate has all required key usage bits.
func verifyKeyUsage(cert *x509.Certificate, masks []uint16) error {
	for _, mask := range masks {
		if uint16(cert.KeyUsage)&mask != mask {
			return fmt.Errorf("openvpn certificate missing required key usage bits: 0x%04x", mask)
		}
	}
	return nil
}

// verifyEKU checks that the certificate has the required extended key usage.
func verifyEKU(cert *x509.Certificate, eku string) error {
	eku = strings.ToLower(strings.TrimSpace(eku))
	var requiredEKU x509.ExtKeyUsage
	switch eku {
	case "server":
		requiredEKU = x509.ExtKeyUsageServerAuth
	case "client":
		requiredEKU = x509.ExtKeyUsageClientAuth
	default:
		return fmt.Errorf("unsupported remote_certificate_eku %q", eku)
	}
	for _, e := range cert.ExtKeyUsage {
		if e == requiredEKU {
			return nil
		}
	}
	return fmt.Errorf("openvpn certificate missing required EKU %q", eku)
}

// parseTLSVersion converts a version string to a tls.ProtocolVersion.
func parseTLSVersion(v string) (uint16, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "":
		return 0, nil
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q", v)
	}
}

var _ net.Conn = (*ControlConn)(nil)
