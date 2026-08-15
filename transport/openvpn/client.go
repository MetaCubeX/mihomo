package openvpn

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/tls"
	"golang.org/x/sync/semaphore"
)

const (
	ControlRetransmitDelay = time.Second

	// renegotiateTimeout bounds initial TLS/KM2 progress. AUTH_PENDING and a
	// continued PUSH_REPLY replace it with their protocol/transition deadline.
	renegotiateTimeout = 30 * time.Second

	// transitionWindow is how long a retiring (lame-duck) data epoch is
	// accepted after a rekey, mirroring OpenVPN's default transition-window.
	transitionWindow = 3600 * time.Second
)

type Client struct {
	config *ClientConfig
	mux    *PacketMux

	control *ControlChannel
	// tlsConn is the active TLS session; swapped on each rekey by the
	// watchControl goroutine and read by Close. Atomic to avoid racing.
	tlsConn atomic.Pointer[tls.Conn]
	// controlEstablishedAt anchors AUTH_PENDING like OpenVPN
	// key_state.established. It is captured after the server KM2 record is
	// parsed and its key material is derived, before deferred-auth messages.
	// Only the handshake/control goroutine reads or replaces it.
	controlEstablishedAt time.Time
	// rekeyHandshakeTimeout bounds TLS/KM2 progress before the server
	// advertises a longer AUTH_PENDING or continuation deadline.
	rekeyHandshakeTimeout time.Duration
	data                  *DataChannel
	outboundKey           *DataChannel
	// outboundStart is when the current outbound-key selection began. It
	// anchors the no-evidence promotion deadline (auth_deferred_expire)
	// used by writeDataPacket when peer evidence never arrives.
	outboundStart time.Time
	// deferredUntil is the active data epoch's AUTH_PENDING deadline.
	// pendingDeferred* temporarily stores a deadline received after KM2 but
	// before installDataChannel creates that epoch. All are protected by
	// dataLock so packet writes and control-message processing agree on the
	// same epoch-bound deadline.
	deferredUntil        time.Time
	pendingDeferredUntil time.Time
	pendingDeferredKeyID uint8
	pendingDeferredSet   bool
	// pushPending accumulates intermediate push-continuation segments across
	// TLS reads until the final segment arrives.
	pushPending             *PushReply
	pushContinuationPending bool
	// retiring is the previous data-channel epoch, kept during a rekey so
	// packets still labeled with the old key ID can be decrypted.
	retiring *DataChannel
	// retiringExpiry is when the retiring epoch is no longer accepted.
	// Pending timestamps are captured when soft reset starts so neither the
	// transition window nor outbound promotion window restarts after TLS/KM2.
	retiringExpiry        time.Time
	pendingRetiringExpiry time.Time
	pendingOutboundStart  time.Time
	push                  *PushReply
	authUser              string
	authPass              string
	// leftoverTLS is unread TLS control bytes after a key-method-2 record.
	leftoverTLS []byte
	// dataChanged is rotated after a new epoch is installed, waking writes
	// paused because the previous key's retiring deadline elapsed mid-rekey.
	dataChanged chan struct{}
	// lastRekeyErr is the original renegotiation failure, preserved because
	// closing the mux otherwise only surfaces "use of closed network connection".
	// Written by watchControl, read by the packet reader: atomic.
	lastRekeyErr atomic.Pointer[error]
	// dataByKey keeps active and retiring data channels indexed by key ID.
	dataByKey map[uint8]*DataChannel
	// controlConn is the net.Conn adapter wrapping the control channel.
	controlConn *ControlConn

	// negotiatedCipher is the data channel cipher selected during the most
	// recent key exchange.
	negotiatedCipher string

	// dataLock protects c.data / c.outboundKey during TLS renegotiation
	// (rekey), where the DataChannel is atomically replaced.
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
		config:                config,
		mux:                   mux,
		control:               NewControlChannel(mux, crypt, local),
		runCtx:                runCtx,
		cancel:                cancel,
		writeSem:              semaphore.NewWeighted(1),
		authUser:              strings.TrimSpace(config.Username),
		authPass:              config.Password,
		dataByKey:             make(map[uint8]*DataChannel),
		dataChanged:           make(chan struct{}),
		rekeyHandshakeTimeout: renegotiateTimeout,
	}
	client.control.transientWriteIsLoss = config.Proto == ProtoUDP
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
	handshakeCtx, cancelHandshake := context.WithCancelCause(ctx)
	defer cancelHandshake(nil)
	interrupt := c.interruptTLSOnDone(handshakeCtx)
	defer interrupt()
	var retransmitStop func()
	defer func() {
		if retransmitStop != nil {
			retransmitStop()
		}
	}()
	if c.config.Proto == ProtoUDP {
		retransmitStop = c.retransmitControl(handshakeCtx, cancelHandshake)
	}

	if err := c.startTLSEpoch(handshakeCtx); err != nil {
		return nil, operationContextError(handshakeCtx, err)
	}

	push, err := c.doKeyExchange(handshakeCtx)
	if err != nil {
		return nil, operationContextError(handshakeCtx, err)
	}
	if retransmitStop != nil {
		retransmitStop()
		retransmitStop = nil
	}
	if cause := context.Cause(handshakeCtx); cause != nil {
		return nil, cause
	}
	_ = c.tlsConn.Load().SetDeadline(time.Time{})
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
	if c.tlsConn.Load() != nil {
		// Drop the old epoch without writing close_notify. Close() would send
		// it on whatever key ID is current and pollute the new control epoch.
		c.tlsConn.Store(nil)
	}
	c.controlConn.Reset()
	// The previous epoch's establishment time must never anchor deferred
	// authentication for this TLS/KM2 epoch.
	c.controlEstablishedAt = time.Time{}
	c.leftoverTLS = nil
	conn := tls.Client(c.controlConn, tlsConfig)
	c.tlsConn.Store(conn)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("openvpn tls handshake: %w", err)
	}
	// Drain any control packets that arrived on the new epoch while the
	// handshake was reading, so they are not acknowledged and dropped by a
	// raw ControlChannel read. A TLS-encrypted P_CONTROL_V1 token update
	// must stay reachable through the active tls.Conn.
	c.consumeQueuedControl()
	return nil
}

// consumeQueuedControl parses queued control packets and routes them back
// into the active TLS stream so the key-method / PUSH exchange can see them.
func (c *Client) consumeQueuedControl() {
	if c.controlConn == nil {
		return
	}
	for _, pkt := range c.control.ReadAll() {
		if pkt.Opcode != PControlV1 || len(pkt.Payload) == 0 {
			continue
		}
		c.controlConn.UnsafeFeed(pkt.Payload)
	}
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
	if _, err := c.tlsConn.Load().Write(clientBytes); err != nil {
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
	// OpenVPN starts AUTH_PENDING from key_state.established, after the peer's
	// KM2 record has been accepted and the new key material is ready.
	c.controlEstablishedAt = time.Now()

	if c.push != nil {
		// Authenticated rekeys keep the previous ifconfig / peer-id.
		// OpenVPN 2.6 often does not send another PUSH_REPLY here, but may
		// push a fresh auth-token (send_push_reply_auth_token) that must be
		// consumed to keep the next key-method-2 auth from expiring. If the
		// server rejected the token (AUTH_FAILED), abort before installing a
		// new data channel rather than proceeding with a stale credential.
		if err := c.consumeRekeyPush(); err != nil {
			return nil, fmt.Errorf("consume rekey push: %w", err)
		}
		push := c.push
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

	if _, err := c.tlsConn.Load().Write([]byte(PushRequest + "\x00")); err != nil {
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

// consumeRekeyPush updates the cached push state after an authenticated
// rekey: it inherits the previous peer-id and applies any fresh auth-token
// pushed by send_push_reply_auth_token. Must be called only when c.push is
// non-nil (i.e. on rekey, not the initial handshake).
func (c *Client) consumeRekeyPush() error {
	var conn pushReadConn
	if tlsConn := c.tlsConn.Load(); tlsConn != nil {
		conn = tlsConn
	}
	return c.consumeRekeyPushFrom(conn, readTokenPushReply)
}

// tokenPushReader is injected by deterministic lifecycle tests; production
// always uses readTokenPushReply with the active TLS connection.
type tokenPushReader func(pushReadConn, []byte, ...time.Time) (*PushReply, []byte, error)

func (c *Client) consumeRekeyPushFrom(conn pushReadConn, readFinal tokenPushReader) error {
	// The token/deferred-push exchange owns every transport deadline installed
	// while it runs. Clear them before returning so standalone parked-TLS calls
	// cannot leak an operation deadline into the established-channel loop.
	defer c.clearControlOperationDeadline()

	base := *c.push
	rekey := &PushReply{PeerID: base.PeerID}
	push := mergePushReply(c.push, rekey)
	complete := false
	attemptedFinalRead := false

	// Terminal control messages have priority over coalesced push data. Check
	// the original buffer before splitControlMessages consumes it.
	if err := controlMessageError(c.leftoverTLS); err != nil {
		return err
	}

	// First consume complete messages already read past KM2.
	reply, rest, ok := takePushReply(c.leftoverTLS)
	c.leftoverTLS = rest
	if reply != nil {
		c.pushPending = mergePushReply(c.pushPending, reply)
		c.applyAuthPendingTimeout(reply)
		if reply.PushContinuation == 2 {
			c.pushContinuationPending = true
		}
	}
	if ok {
		complete = true
		c.pushContinuationPending = false
	}
	if err := controlMessageError(c.leftoverTLS); err != nil {
		return err
	}

	// If no final PUSH_REPLY has arrived yet, probe the active TLS stream.
	// This includes standalone AUTH_PENDING and intermediate continuation
	// segments; neither is allowed to complete the rekey by itself.
	if !complete && conn != nil {
		attemptedFinalRead = true
		continuationLimit := c.rekeyWaitDeadline(time.Now())
		deadline := time.Time{}
		if c.pushContinuationPending {
			deadline = continuationLimit
		}
		more, newRest, err := readFinal(conn, c.leftoverTLS, deadline, c.controlEstablishedAt, continuationLimit)
		if err != nil {
			return err
		}
		c.leftoverTLS = newRest
		if more != nil {
			c.pushPending = mergePushReply(c.pushPending, more)
			c.applyAuthPendingTimeout(more)
			complete = more.HasPushReply && more.PushContinuation != 2
			if more.HasPushReply {
				// Persist continuation state regardless of whether it was already
				// buffered or was first discovered inside the final reader.
				c.pushContinuationPending = more.PushContinuation == 2
			}
		}
	}

	if attemptedFinalRead && c.pushContinuationPending {
		return errors.New("openvpn continued push reply incomplete")
	}
	if !complete && c.pushPending != nil && !c.pushPending.HasPushReply {
		// AUTH_PENDING is standalone metadata, not the first half of a push.
		// A deferred-auth rekey without auth-gen-token legally has no final
		// PUSH_REPLY. Its deadline has already been staged for this key epoch;
		// discard only the accumulator metadata and retain the cached push.
		c.pushPending = nil
	}
	if complete && c.pushPending != nil {
		push = mergePushReply(push, c.pushPending)
		c.pushPending = nil
	}
	c.push = push
	c.captureAuthToken(push)
	return nil
}

func (c *Client) consumeParkedRekeyPush() error {
	c.consumeQueuedControl()
	if c.push != nil {
		return c.consumeRekeyPush()
	}
	// Keep the ownership explicit even when no cached push exists.
	c.clearControlOperationDeadline()
	return nil
}

func (c *Client) clearControlOperationDeadline() {
	if conn := c.tlsConn.Load(); conn != nil {
		_ = conn.SetDeadline(time.Time{})
	}
	if c.controlConn != nil {
		_ = c.controlConn.SetDeadline(time.Time{})
	}
}

// applyAuthPendingTimeout records a server-advertised AUTH_PENDING,timeout N
// for the matching control/data epoch.
func (c *Client) applyAuthPendingTimeout(reply *PushReply) {
	if reply == nil || !pushHasAuthPending(reply) {
		return
	}
	anchorAuthPendingDeadline(reply, c.controlEstablishedAt)
	deadline := reply.authPendingUntil
	keyID := c.control.KeyID()
	c.dataLock.Lock()
	if c.data != nil && c.data.keyID == keyID {
		// AUTH_PENDING is an update, not an extension-only hint: OpenVPN
		// replaces the timeout for this authentication session even when the
		// newly proposed deadline is shorter.
		c.deferredUntil = deadline
	} else {
		// KM2/control has advanced to keyID but installDataChannel has not
		// installed that data epoch. Stage the latest deadline with the key ID;
		// install will transfer it only to the matching epoch.
		c.pendingDeferredKeyID = keyID
		c.pendingDeferredUntil = deadline
		c.pendingDeferredSet = true
	}
	c.dataLock.Unlock()

	if conn := c.tlsConn.Load(); conn != nil {
		_ = conn.SetDeadline(deadline)
	}
	if c.controlConn != nil {
		_ = c.controlConn.SetDeadline(deadline)
	}
}

func (c *Client) effectiveControlDeadline(fallback time.Time) time.Time {
	keyID := c.control.KeyID()
	c.dataLock.RLock()
	deferred := c.deferredUntil
	dataMatches := c.data != nil && c.data.keyID == keyID
	pending := c.pendingDeferredUntil
	pendingMatches := c.pendingDeferredSet && c.pendingDeferredKeyID == keyID
	c.dataLock.RUnlock()
	// AUTH_PENDING replaces the operation timeout for its exact key epoch;
	// it may extend or shorten the original context deadline. Pending state
	// wins before installDataChannel, active state afterwards.
	if pendingMatches {
		return pending
	}
	if dataMatches && !deferred.IsZero() {
		return deferred
	}
	return fallback
}

// authDeferredExpire is the no-evidence promotion window for the outbound
// data key, mirroring OpenVPN's auth_deferred_expire_window
// (ssl.c): min(handshake_window, reneg_seconds/2). With defaults that is
// min(60, 1800) = 60s. tls_select_encryption_key switches outbound to the
// new key once it is authenticated, which happens inside this window, so
// this is the correct deadline for promoting without peer evidence.
const authDeferredExpire = 60 * time.Second
const authPendingMaxTimeout = 30 * time.Minute

func (c *Client) transitionWindow() time.Duration {
	window := transitionWindow
	if c.config != nil && (c.config.TransitionWindowSet || c.config.TransitionWindow > 0) {
		window = c.config.TransitionWindow
	}
	return window
}

func (c *Client) retiringWindowDeadline(reset *ControlPacket) time.Time {
	acceptedAt := time.Now()
	if reset != nil && !reset.receivedAt.IsZero() {
		acceptedAt = reset.receivedAt
	}
	return acceptedAt.Add(c.transitionWindow())
}

func (c *Client) stageRetiringWindow(deadline time.Time) {
	if deadline.IsZero() {
		return
	}
	c.dataLock.Lock()
	c.pendingRetiringExpiry = deadline
	c.pendingOutboundStart = deadline.Add(-c.transitionWindow())
	c.dataLock.Unlock()
}

func (c *Client) signalDataChangedLocked() {
	if c.dataChanged != nil {
		close(c.dataChanged)
	}
	c.dataChanged = make(chan struct{})
}

// installDataChannel records a freshly derived data epoch. Decryption can
// immediately use the new key (the peer may label packets with it), but the
// outbound key is deliberately kept on the previous epoch until there is
// evidence the peer has activated the new one, mirroring OpenVPN's deferred
// auth key selection.
//
// OpenVPN (ssl.c: tls_select_encryption_key / key_state_soft_reset) only
// selects a key for outbound encryption once it is KS_AUTH_TRUE. During
// deferred authentication the new key stays KS_AUTH_DEFERRED — the server
// sends its key-method-2 record before generating its data key — so the
// lame-duck key keeps encrypting outbound traffic. Switching outbound to the
// new key immediately would send packets the server drops ("not authorized
// (deferred)").
func (c *Client) installDataChannel(newData *DataChannel) {
	c.dataLock.Lock()
	old := c.data
	c.retiring = old
	c.data = newData
	// Outbound keeps the previous epoch whenever one exists (OpenVPN
	// key_state_soft_reset moves the old primary into the lame-duck slot and
	// tls_select_encryption_key keeps selecting it until the new key is
	// authenticated). Only the very first handshake (old == nil) starts on
	// the new key immediately. An epoch's send counter is irrelevant: a
	// quiet / receive-only tunnel never sends on the old key, but the old
	// key is still the correct outbound candidate during deferred auth.
	if old != nil {
		c.outboundKey = old
	} else {
		c.outboundKey = newData
	}
	// The no-evidence promotion deadline belongs to the key state and starts
	// when its soft reset was accepted, not when slow TLS/KM2 work finishes.
	c.outboundStart = time.Now()
	if old != nil && !c.pendingOutboundStart.IsZero() {
		c.outboundStart = c.pendingOutboundStart
	}
	c.pendingOutboundStart = time.Time{}
	c.deferredUntil = time.Time{}
	if c.pendingDeferredSet && c.pendingDeferredKeyID == newData.keyID {
		c.deferredUntil = c.pendingDeferredUntil
	}
	c.pendingDeferredUntil = time.Time{}
	c.pendingDeferredKeyID = 0
	c.pendingDeferredSet = false
	if c.dataByKey == nil {
		c.dataByKey = make(map[uint8]*DataChannel)
	}
	if old != nil && old.keyID != newData.keyID {
		c.dataByKey[old.keyID] = old
	}
	c.dataByKey[newData.keyID] = newData
	// The previous epoch is a lame-duck key: keep it only until the absolute
	// transition deadline captured when the peer's soft reset was accepted.
	if old != nil {
		if !c.pendingRetiringExpiry.IsZero() {
			c.retiringExpiry = c.pendingRetiringExpiry
		} else {
			c.retiringExpiry = time.Now().Add(c.transitionWindow())
		}
	} else {
		c.retiringExpiry = time.Time{}
	}
	c.pendingRetiringExpiry = time.Time{}
	// Keep at most the current and previous epoch.
	for id := range c.dataByKey {
		if id != newData.keyID && (old == nil || id != old.keyID) {
			delete(c.dataByKey, id)
		}
	}
	c.signalDataChangedLocked()
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
	if user != "" {
		c.authUser = user
	}
	c.authPass = pass
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
	if compress && c.config.CompLZO == CompLzoYes {
		compressed, err := lzo1xCompressSafe(packet)
		if err != nil {
			return err
		}
		packet = compressed
	}

	// The no-evidence selection window is independent of AUTH_PENDING. The
	// server-advertised timeout controls deferred authentication/push handling;
	// it cannot keep a retiring data key selected past auth_deferred_expire.
	selectionExpired := func() bool {
		return time.Now().After(c.outboundStart.Add(authDeferredExpire))
	}
	retiringExpired := func() bool {
		return c.retiring != nil && c.outboundKey == c.retiring &&
			!c.retiringExpiry.IsZero() && time.Now().After(c.retiringExpiry)
	}

	for {
		// Select under the state lock, upgrading only when promotion is due.
		c.dataLock.RLock()
		data := c.data
		if data == nil {
			c.dataLock.RUnlock()
			return errors.New("openvpn data channel is not ready")
		}
		if !c.pendingRetiringExpiry.IsZero() && time.Now().After(c.pendingRetiringExpiry) {
			changed := c.dataChanged
			c.dataLock.RUnlock()
			// Fail closed without tearing down the tunnel: pause ordinary data
			// writes until installDataChannel publishes the new usable epoch.
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return ctx.Err()
			case <-c.runCtx.Done():
				return net.ErrClosed
			}
		}
		outbound := c.outboundKey
		if outbound == nil {
			outbound = data
		}
		needPromote := outbound != data &&
			(data.PeerActive() || selectionExpired() || retiringExpired())
		c.dataLock.RUnlock()
		if needPromote {
			c.dataLock.Lock()
			if c.outboundKey != c.data && c.outboundKey != nil &&
				(c.data.PeerActive() || selectionExpired() || retiringExpired()) {
				c.outboundKey = c.data
				c.outboundStart = time.Now()
			}
			c.dataLock.Unlock()
			continue
		}

		// A second rekey may have completed after selection. Revalidate the
		// pointer, then keep the read lock through encryption so
		// installDataChannel cannot retire this epoch while crypto is in flight.
		c.dataLock.RLock()
		if !c.pendingRetiringExpiry.IsZero() && time.Now().After(c.pendingRetiringExpiry) {
			changed := c.dataChanged
			c.dataLock.RUnlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return ctx.Err()
			case <-c.runCtx.Done():
				return net.ErrClosed
			}
		}
		valid := c.dataByKey[outbound.keyID] == outbound &&
			(outbound == c.data || outbound == c.retiring || outbound == c.outboundKey)
		if !valid {
			c.dataLock.RUnlock()
			continue
		}
		if outbound != c.data &&
			(c.data.PeerActive() || selectionExpired() || retiringExpired()) {
			c.dataLock.RUnlock()
			continue
		}
		encrypted, err := outbound.Encrypt(packet)
		c.dataLock.RUnlock()
		if err != nil {
			return err
		}
		// Once encryption completed under the epoch lock, the packet is an
		// in-flight datagram. Release state before transport I/O: network delay
		// can naturally carry a valid packet across a later rekey, and a blocked
		// socket must not prevent installDataChannel from committing that rekey.
		if err := c.mux.WritePacket(ctx, encrypted); err != nil {
			return err
		}
		c.markSend()
		return nil
	}
}

func (c *Client) LastRekeyError() error {
	if err := c.lastRekeyErr.Load(); err != nil {
		return *err
	}
	return nil
}

func (c *Client) ReadIPPacket(ctx context.Context) ([]byte, error) {
	for {
		packet, err := c.mux.ReadDataPacket(ctx)
		if err != nil {
			// Only surface the rekey failure when the transport is actually
			// being torn down; do not pollute unrelated read errors.
			if errors.Is(err, net.ErrClosed) {
				if rekeyErr := c.LastRekeyError(); rekeyErr != nil {
					return nil, fmt.Errorf("%w: %v", err, rekeyErr)
				}
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
	if !c.pendingRetiringExpiry.IsZero() && time.Now().After(c.pendingRetiringExpiry) {
		c.dataLock.RUnlock()
		return nil, errors.New("openvpn data packet after retiring deadline while rekey is in progress")
	}
	// The retiring (lame-duck) epoch is rejected once the transition window
	// has elapsed, even though it still has a dataByKey entry (the map hit
	// must not bypass the expiration check).
	if c.retiring != nil && c.retiring.keyID == keyID &&
		!c.retiringExpiry.IsZero() && time.Now().After(c.retiringExpiry) {
		c.dataLock.RUnlock()
		return nil, errors.New("openvpn data packet from expired retiring epoch")
	}
	// Route strictly by key ID. A packet labeled with an unknown epoch must
	// be rejected, not silently decrypted with the current key (the CBC HMAC
	// excludes the outer opcode/key-ID header, so a wrong key would still
	// "authenticate"). Keep the read lock through authentication/decryption
	// so a concurrent rekey cannot remove the selected epoch mid-packet.
	data := c.dataByKey[keyID]
	if data == nil {
		c.dataLock.RUnlock()
		return nil, errors.New("openvpn data packet with unknown key id")
	}
	isNewest := data == c.data
	plain, err := data.Decrypt(packet)
	c.dataLock.RUnlock()
	if err != nil {
		return nil, err
	}
	if isNewest {
		// The peer labeled an outbound packet with the current key ID, so it
		// has activated this epoch (OpenVPN only labels outbound with a key
		// whose auth completed). Mark the epoch itself: even if a rekey
		// swapped c.data between the RLock and here, the evidence stays on
		// this epoch and cannot be attributed to a newer key.
		data.MarkPeerActive()
	}
	return plain, nil
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
			if c.runCtx.Err() != nil {
				return
			}
			if errors.Is(err, errParkedTLS) {
				// A same-epoch TLS payload (token update / late AUTH_FAILED)
				// was parked. Consume it now so a deferred authentication
				// failure is surfaced immediately instead of waiting for the
				// next soft reset (which may never come). This is a standalone
				// control operation, so clear every deadline it installs before
				// returning to the established-channel wait loop.
				if consumeErr := c.consumeParkedRekeyPush(); consumeErr != nil {
					if c.runCtx.Err() == nil {
						c.failControl(fmt.Errorf("consume parked rekey push: %w", consumeErr))
					}
					return
				}
				continue
			}
			c.failControl(fmt.Errorf("wait for soft reset: %w", err))
			return
		}
		// OpenVPN starts the retiring (lame-duck) key lifetime when it accepts
		// the soft reset. Capture that absolute deadline before probing the old
		// TLS epoch; the optional token probe may consume tokenPushReadTimeout.
		retiringExpiry := c.retiringWindowDeadline(packet)
		c.stageRetiringWindow(retiringExpiry)
		// Token-only PUSH_REPLY parked since the last rekey must land in
		// authPass before this key-method-2 exchange, otherwise the server
		// rejects the expired token. A parked AUTH_FAILED (deferred auth) is
		// a hard failure: surface it before starting the next epoch instead
		// of replacing it with the next renegotiation result.
		c.consumeQueuedControl()
		if c.push != nil {
			if err := c.consumeRekeyPush(); err != nil {
				if c.runCtx.Err() == nil {
					c.failControl(fmt.Errorf("consume queued rekey push: %w", err))
				}
				return
			}
		}
		if err := c.renegotiate(packet, retiringExpiry); err != nil {
			if c.runCtx.Err() == nil {
				// A soft reset has already advanced the reliable control epoch and
				// started a new TLS byte stream, so rolling back is not safe. Keep
				// carrying data on the retiring key while advertised auth/push
				// deadlines remain valid; after those deadlines, fail closed rather
				// than leave a half-transitioned control channel alive indefinitely.
				c.failControl(fmt.Errorf("renegotiate: %w", err))
			}
			return
		}
	}
}

func (c *Client) failControl(err error) {
	c.lastRekeyErr.Store(&err)
	c.cancel()
	_ = c.mux.Close()
}

// errRenegotiateNoTLS is returned when renegotiate() is called before a TLS
// connection has been established.
var errRenegotiateNoTLS = errors.New("cannot renegotiate: tls connection not established")

// renegotiate performs a single TLS epoch restart:
// 1. Send our own soft reset to acknowledge the server's rekey request
// 2. Start a fresh TLS session over the existing reliable ControlConn
// 3. Exchange fresh key method 2 records and derive new data channel keys
// 4. Atomically replace c.data with the new DataChannel
func (c *Client) renegotiate(serverReset *ControlPacket, retiringExpiry time.Time) error {
	if c.tlsConn.Load() == nil && c.controlConn == nil {
		return errRenegotiateNoTLS
	}
	renegCtx, cancelReneg := context.WithCancelCause(c.runCtx)
	defer cancelReneg(nil)
	interrupt := c.interruptTLSOnDone(renegCtx)
	defer interrupt()
	defer func() {
		if c.controlConn != nil {
			_ = c.controlConn.SetDeadline(time.Time{})
		}
	}()
	if c.controlConn != nil {
		_ = c.controlConn.SetDeadline(time.Now().Add(c.rekeyTimeout()))
	}

	// The watcher captures this absolute deadline as soon as it accepts the
	// peer's soft reset, before probing the previous TLS stream. Stage that
	// exact value for installDataChannel; never restart the transition window
	// after token probing, TLS, or KM2 processing.
	if !retiringExpiry.IsZero() {
		c.dataLock.Lock()
		c.pendingRetiringExpiry = retiringExpiry
		c.pendingOutboundStart = retiringExpiry.Add(-c.transitionWindow())
		c.dataLock.Unlock()
	}

	keyID := NextKeyID(c.control.KeyID())
	if serverReset != nil {
		keyID = serverReset.KeyID & KeyIDMask
	}
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

	// On UDP, the client soft reset, TLS ClientHello and the TLS control
	// records are reliable control messages. Retransmit them while the
	// rekey is in flight; losing any single datagram would otherwise stall
	// the rekey until the current protocol deadline.
	var retransmitStop func()
	defer func() {
		if retransmitStop != nil {
			retransmitStop()
		}
	}()
	if c.config.Proto == ProtoUDP {
		retransmitStop = c.retransmitControl(renegCtx, cancelReneg)
	}

	if err := c.startTLSEpoch(renegCtx); err != nil {
		return operationContextError(renegCtx, fmt.Errorf("tls epoch handshake: %w", err))
	}

	if _, err := c.doKeyExchange(renegCtx); err != nil {
		return operationContextError(renegCtx, fmt.Errorf("rekey exchange: %w", err))
	}
	if retransmitStop != nil {
		retransmitStop()
		retransmitStop = nil
	}
	if cause := context.Cause(renegCtx); cause != nil {
		return cause
	}
	return nil
}

// retransmitControl retransmits unacked control messages every
// ControlRetransmitDelay while ctx is live. It is the UDP reliability path
// for initial and renegotiated TLS epochs.
func (c *Client) retransmitControl(ctx context.Context, fail ...context.CancelCauseFunc) (stop func()) {
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(ControlRetransmitDelay)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := c.control.RetransmitPending(loopCtx); err != nil {
					if loopCtx.Err() != nil &&
						(errors.Is(err, context.Canceled) || retryableControlWriteError(err)) {
						return
					}
					if retryableControlWriteError(err) {
						continue
					}
					if len(fail) > 0 && fail[0] != nil {
						fail[0](fmt.Errorf("retransmit openvpn control packet: %w", err))
					}
					return
				}
			case <-loopCtx.Done():
				return
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func (c *Client) rekeyTimeout() time.Duration {
	if c.rekeyHandshakeTimeout > 0 {
		return c.rekeyHandshakeTimeout
	}
	return renegotiateTimeout
}

func (c *Client) rekeyWaitDeadline(now time.Time) time.Time {
	deadline := now.Add(c.rekeyTimeout())
	c.dataLock.RLock()
	retiringExpiry := c.pendingRetiringExpiry
	c.dataLock.RUnlock()
	if retiringExpiry.After(deadline) {
		deadline = retiringExpiry
	}
	return deadline
}

func retryableControlWriteError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary())
}

func operationContextError(ctx context.Context, fallback error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return fallback
}

// interruptTLSOnDone makes cancellation observable to tls.Conn reads backed
// by ControlConn, whose packet read otherwise has no context parameter.
func (c *Client) interruptTLSOnDone(ctx context.Context) func() {
	stop := contextutils.AfterFunc(ctx, func() {
		if conn := c.tlsConn.Load(); conn != nil {
			_ = conn.SetDeadline(time.Now())
		}
	})
	return func() { _ = stop() }
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
	if conn := c.tlsConn.Load(); conn != nil {
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
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
					if retryableControlWriteError(err) {
						retransmits++
						continue
					}
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

const maxTLSControlBuffer = 1 << 20

func appendTLSControl(buf, data []byte) ([]byte, error) {
	if len(data) > maxTLSControlBuffer-len(buf) {
		return nil, fmt.Errorf("openvpn TLS control buffer exceeds %d bytes", maxTLSControlBuffer)
	}
	return append(buf, data...), nil
}

func (c *Client) readServerKeyMethod(ctx context.Context) (*KeyMethod2Record, error) {
	return c.readServerKeyMethodFrom(ctx, c.tlsConn.Load())
}

func (c *Client) readServerKeyMethodFrom(ctx context.Context, conn pushReadConn) (*KeyMethod2Record, error) {
	buf := append([]byte(nil), c.leftoverTLS...)
	c.leftoverTLS = nil
	if len(buf) > maxTLSControlBuffer {
		return nil, fmt.Errorf("openvpn TLS control buffer exceeds %d bytes", maxTLSControlBuffer)
	}
	tmp := make([]byte, 4096)
	var readErr error
	for {
		// Only treat the record as complete when all four strings are
		// present. A standard record fragmented across TLS reads must not
		// be accepted early (its tail would be mistaken for PUSH_REPLY).
		if complete, _ := RecordComplete(buf); complete {
			record, consumed, err := ParseServerKeyMethod2RecordConsumed(buf)
			if err != nil {
				return nil, err
			}
			c.leftoverTLS = append([]byte(nil), buf[consumed:]...)
			return record, nil
		}
		// A shortened 2.6 record may end after options when the following
		// PUSH_REPLY/AUTH_FAILED is already visible. Only truncation means read
		// more; invalid prefix/method and other definitive errors fail now.
		record, consumed, parseErr := ParseServerKeyMethod2RecordConsumed(buf)
		if parseErr == nil {
			c.leftoverTLS = append([]byte(nil), buf[consumed:]...)
			return record, nil
		}
		if !errors.Is(parseErr, errKeyMethodPacketTooShort) && !errors.Is(parseErr, ioStringEOF) {
			return nil, parseErr
		}
		if readErr != nil {
			return nil, fmt.Errorf("read key method 2 server record: %w", readErr)
		}
		deadline := time.Time{}
		if d, ok := ctx.Deadline(); ok {
			deadline = d
		}
		deadline = c.effectiveControlDeadline(deadline)
		if !deadline.IsZero() {
			_ = conn.SetDeadline(deadline)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf, readErr = appendTLSControl(buf, tmp[:n])
			if readErr != nil {
				return nil, readErr
			}
		}
		readErr = err
	}
}

func (c *Client) readPushReply(ctx context.Context) (*PushReply, error) {
	return c.readPushReplyFrom(ctx, c.tlsConn.Load())
}

func (c *Client) readPushReplyFrom(ctx context.Context, conn pushReadConn) (*PushReply, error) {
	buf := append([]byte(nil), c.leftoverTLS...)
	c.leftoverTLS = nil
	if len(buf) > maxTLSControlBuffer {
		return nil, fmt.Errorf("openvpn TLS control buffer exceeds %d bytes", maxTLSControlBuffer)
	}
	tmp := make([]byte, 4096)
	var readErr error
	var continuationDeadline time.Time
	for {
		if err := controlMessageError(buf); err != nil {
			return nil, err
		}
		reply, rest, ok := takePushReply(buf)
		if ok {
			c.leftoverTLS = rest
			if c.pushPending != nil {
				reply = mergePushReply(c.pushPending, reply)
				c.pushPending = nil
			}
			c.applyAuthPendingTimeout(reply)
			return reply, nil
		}
		if reply != nil {
			// Intermediate continuation segment(s) or AUTH_PENDING seen but
			// the final PUSH_REPLY segment has not arrived: accumulate and
			// keep reading. During rekey this deadline reaches the retiring
			// key's transition expiry instead of the initial 30-second bound.
			buf = append([]byte(nil), rest...)
			c.pushPending = mergePushReply(c.pushPending, reply)
			c.applyAuthPendingTimeout(reply)
			if reply.PushContinuation == 2 && continuationDeadline.IsZero() {
				continuationDeadline = c.rekeyWaitDeadline(time.Now())
			}
		}
		if readErr != nil {
			return nil, fmt.Errorf("read push reply: %w", readErr)
		}
		deadline := time.Time{}
		if d, ok := ctx.Deadline(); ok {
			deadline = d
		}
		deadline = c.effectiveControlDeadline(deadline)
		if !continuationDeadline.IsZero() && (deadline.IsZero() || continuationDeadline.Before(deadline)) {
			deadline = continuationDeadline
		}
		if !deadline.IsZero() {
			_ = conn.SetDeadline(deadline)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf, readErr = appendTLSControl(buf, tmp[:n])
			if readErr != nil {
				return nil, readErr
			}
		}
		readErr = err
	}
}

// tokenPushReadTimeout bounds how long a rekey waits for a token-only
// PUSH_REPLY after the server key-method-2 record. OpenVPN pushes the fresh
// auth-token in the same TLS session right after the record, but never
// blocks on it; a timeout keeps rekeys from stalling.
const tokenPushReadTimeout = 300 * time.Millisecond

// errAuthFailed is returned when a rekey's token exchange reports
// AUTH_FAILED instead of a renewed token.
var errAuthFailed = errors.New("openvpn authentication failed")

// pushReadConn is the subset of tls.Conn that readTokenPushReply needs, so
// tests can inject a deterministic byte-stream reader without a full TLS
// handshake.
type pushReadConn interface {
	Read(p []byte) (int, error)
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
}

// readTokenPushReply tries to consume a token-only PUSH_REPLY (an
// auth-token renewal pushed by send_push_reply_auth_token) from the TLS
// stream, without stalling a rekey. leftover holds bytes already read past
// the server key-method-2 record.
//
// TLS is a byte stream: the reply may be split across reads, so the buffer
// is parsed after every read including the final one. On timeout the
// buffered bytes are preserved and a nil reply (no error) is returned, so a
// partially-received reply is not lost. AUTH_FAILED is a hard error.
func readTokenPushReply(conn pushReadConn, leftover []byte, extended ...time.Time) (*PushReply, []byte, error) {
	buf := append([]byte(nil), leftover...)
	if len(buf) > maxTLSControlBuffer {
		return nil, nil, fmt.Errorf("openvpn TLS control buffer exceeds %d bytes", maxTLSControlBuffer)
	}
	tmp := make([]byte, 4096)
	var acc *PushReply
	var waitUntil time.Time
	var continuationUntil time.Time
	if len(extended) > 0 {
		continuationUntil = extended[0]
		waitUntil = continuationUntil
	}
	establishedAt := time.Time{}
	if len(extended) > 1 {
		establishedAt = extended[1]
	}
	continuationLimit := time.Time{}
	if len(extended) > 2 {
		continuationLimit = extended[2]
	}
	var authPendingUntil time.Time
	promoteWaitPolicy := func(reply *PushReply) {
		if reply == nil {
			return
		}
		now := time.Now()
		if pushHasAuthPending(reply) {
			anchorAuthPendingDeadline(reply, establishedAt)
			deadline := reply.authPendingUntil
			authPendingUntil = deadline
			if !continuationUntil.IsZero() {
				waitUntil = continuationUntil
				if authPendingUntil.Before(waitUntil) {
					waitUntil = authPendingUntil
				}
			}
			_ = conn.SetDeadline(deadline)
		}
		if reply.PushContinuation == 2 && continuationUntil.IsZero() {
			continuationUntil = continuationLimit
			if continuationUntil.IsZero() {
				continuationUntil = now.Add(renegotiateTimeout)
			}
			waitUntil = continuationUntil
			if !authPendingUntil.IsZero() && authPendingUntil.Before(waitUntil) {
				waitUntil = authPendingUntil
			}
			_ = conn.SetDeadline(waitUntil)
		}
	}
	// Parse the already-buffered bytes first; a reply may be fully present.
	// Intermediate push-continuation segments are accumulated in acc until
	// the final segment arrives.
	if err := controlMessageError(buf); err != nil {
		return nil, buf, err
	}
	if reply, rest, ok := takePushReply(buf); ok {
		return mergePushReply(acc, reply), rest, nil
	} else if reply != nil {
		acc = mergePushReply(acc, reply)
		promoteWaitPolicy(reply)
		buf = append([]byte(nil), rest...)
	}
	if err := controlMessageError(buf); err != nil {
		return nil, buf, err
	}
	// Restore only the temporary read deadline on every return path. A
	// successful parse must not leave a short probe deadline for the next
	// waitForSoftReset read. SetDeadline above deliberately leaves the
	// AUTH_PENDING/continuation write side extended so late reliable ACKs can
	// still be emitted; the owner clears both sides when the operation ends.
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	for attempt := 0; ; attempt++ {
		readDeadline := time.Now().Add(tokenPushReadTimeout)
		if !waitUntil.IsZero() && waitUntil.Before(readDeadline) {
			readDeadline = waitUntil
		}
		_ = conn.SetReadDeadline(readDeadline)
		n, err := conn.Read(tmp)
		// Process bytes before handling err: the io.Reader contract permits
		// n > 0 with err != nil. The bytes are valid before the terminal error.
		if n > 0 {
			var appendErr error
			buf, appendErr = appendTLSControl(buf, tmp[:n])
			if appendErr != nil {
				return nil, buf, appendErr
			}
		}
		if controlErr := controlMessageError(buf); controlErr != nil {
			return nil, buf, controlErr
		}
		reply, rest, ok := takePushReply(buf)
		if reply != nil {
			acc = mergePushReply(acc, reply)
			promoteWaitPolicy(reply)
			buf = append([]byte(nil), rest...)
		}
		if ok {
			return acc, rest, nil
		}
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if !continuationUntil.IsZero() && time.Now().Before(waitUntil) {
					continue
				}
				return acc, buf, nil
			}
			return nil, buf, err
		}
		// Normal token refresh, including standalone AUTH_PENDING metadata, is
		// a short probe. Only an unfinished continuation waits until waitUntil.
		if continuationUntil.IsZero() && attempt+1 >= 2 {
			return acc, buf, nil
		}
		if !continuationUntil.IsZero() && !time.Now().Before(waitUntil) {
			return acc, buf, nil
		}
	}
}

// authFailedMsg reports whether the TLS plaintext buffer contains a complete
// AUTH_FAILED control message (not a partial prefix).
func authFailedMsg(buf []byte) bool {
	msgs, _ := splitControlMessages(buf)
	for _, m := range msgs {
		if bytes.HasPrefix(m, []byte("AUTH_FAILED")) {
			return true
		}
	}
	return false
}

func authFailedError(buf []byte) error {
	msgs, _ := splitControlMessages(buf)
	for _, m := range msgs {
		if bytes.HasPrefix(m, []byte("AUTH_FAILED")) {
			return fmt.Errorf("%w: %s", errAuthFailed, strings.TrimSpace(string(m)))
		}
	}
	return errAuthFailed
}

var errControlTerminated = errors.New("openvpn server terminated the control session")

func controlMessageError(buf []byte) error {
	if authFailedMsg(buf) {
		return authFailedError(buf)
	}
	msgs, _ := splitControlMessages(buf)
	for _, m := range msgs {
		for _, prefix := range []string{"RESTART", "HALT", "EXIT"} {
			if bytes.HasPrefix(m, []byte(prefix)) {
				return fmt.Errorf("%w: %s", errControlTerminated, strings.TrimSpace(string(m)))
			}
		}
		if bytes.HasPrefix(m, []byte("PUSH_REPLY")) {
			if _, err := parsePushReplyInner(string(m)); err != nil {
				return fmt.Errorf("invalid openvpn push reply: %w", err)
			}
		}
	}
	return nil
}

func pushHasAuthPending(reply *PushReply) bool {
	return reply != nil && (reply.hasAuthPending || reply.AuthPendingTimeout != 0)
}

func anchorAuthPendingDeadline(reply *PushReply, establishedAt time.Time) {
	if !pushHasAuthPending(reply) || !reply.authPendingUntil.IsZero() {
		return
	}
	if establishedAt.IsZero() {
		establishedAt = time.Now()
	}
	reply.authPendingUntil = establishedAt.Add(reply.AuthPendingTimeout)
}

func takePushReply(buf []byte) (*PushReply, []byte, bool) {
	// A single caller handles the happy path (PUSH_REPLY), the failure path
	// (AUTH_FAILED) and the deferred-auth signal (AUTH_PENDING,timeout N).
	// Walk complete NUL-delimited control messages in order so a stream like
	//   AUTH_PENDING,timeout 60\0INFO_PRE,...\0PUSH_REPLY,auth-token ...\0
	// yields the token even though PUSH_REPLY is not first.
	msgs, rest := splitControlMessages(buf)
	if len(msgs) == 0 {
		return nil, rest, false
	}
	var authFailed []byte
	var reply *PushReply
	parsed := false
	// continuationPending is true when the most recent PUSH_REPLY was an
	// intermediate segment (push-continuation 2) and the final segment has
	// not arrived yet.
	continuationPending := false
	for _, m := range msgs {
		if bytes.HasPrefix(m, []byte("AUTH_FAILED")) {
			authFailed = m
			continue
		}
		if bytes.HasPrefix(m, []byte("AUTH_PENDING")) {
			// OpenVPN send_auth_pending_messages / receive_auth_pending:
			// AUTH_PENDING,timeout N extends the deferred-auth window. Parse
			// the advertised timeout so the outbound-key backstop respects
			// it. AUTH_PENDING alone is NOT a complete push reply — the
			// reply is only complete once a final PUSH_REPLY arrives.
			if r, err := parseAuthPendingTimeout(string(m)); err == nil {
				reply = mergePushReply(reply, r)
			}
			continue
		}
		if bytes.HasPrefix(m, []byte("PUSH_REPLY")) {
			r, err := parsePushReplyInner(string(m))
			if err == nil {
				reply = mergePushReply(reply, r)
				parsed = true
				// An intermediate continuation segment (push-continuation 2)
				// means more segments follow; only the final segment (1 or
				// absent) completes the reply.
				continuationPending = r.PushContinuation == 2
				continue
			}
		}
		// Other complete control messages (INFO_PRE, INFO, RESTART, HALT,
		// EXIT, CR_RESPONSE, ...) are deliberately consumed.
	}
	if authFailed != nil {
		// Surface the failure to callers (readTokenPushReply /
		// consumeRekeyPush / readPushReply) via the rest-of-buffer, since
		// takePushReply's ok=false is also used for "not complete yet".
		return nil, rest, false
	}
	if !parsed || continuationPending {
		// Nothing usable, or only intermediate continuation segments so far:
		// not a complete reply. The parsed reply (with the intermediate
		// segments merged and the AUTH_PENDING timeout) is returned so the
		// caller can accumulate it across reads.
		return reply, rest, false
	}
	return reply, rest, true
}

// parseAuthPendingTimeout parses an AUTH_PENDING[,timeout N] control message
// and returns a PushReply carrying the advertised deferred-auth timeout.
func parseAuthPendingTimeout(msg string) (*PushReply, error) {
	reply := &PushReply{
		PeerID:             PeerIDUnset,
		AuthPendingTimeout: authDeferredExpire, // bare AUTH_PENDING fallback
		hasAuthPending:     true,
	}
	if !strings.HasPrefix(msg, "AUTH_PENDING") {
		return nil, errors.New("not an auth pending message")
	}
	rest := strings.TrimPrefix(msg, "AUTH_PENDING")
	rest = strings.TrimPrefix(rest, ",")
	// OpenVPN caps explicit timeouts at max(reneg-sec/2, hand-window).
	// Mihomo currently implements the reference defaults: max(1800, 60).
	for _, part := range strings.Split(rest, ",") {
		fields := strings.Fields(part)
		if len(fields) != 2 || fields[0] != "timeout" {
			continue
		}
		seconds, err := strconv.ParseUint(fields[1], 10, 64)
		maxSeconds := uint64(authPendingMaxTimeout / time.Second)
		if err == nil {
			if seconds > maxSeconds {
				seconds = maxSeconds
			}
			reply.AuthPendingTimeout = time.Duration(seconds) * time.Second
		} else if errors.Is(err, strconv.ErrRange) {
			reply.AuthPendingTimeout = authPendingMaxTimeout
		}
	}
	return reply, nil
}

// splitControlMessages splits a TLS plaintext byte stream into complete
// NUL-terminated control messages and returns the trailing bytes that do not
// yet form a complete message. OpenVPN frames every control message with a
// trailing NUL (send_control_channel_string_dowork), and the client parses
// them one by one (forward.c check_incoming_control_channel /
// extract_command_buffer). The trailing incomplete message is returned as
// rest so it can be re-merged when the next TLS read arrives.
func splitControlMessages(buf []byte) ([][]byte, []byte) {
	if len(buf) == 0 {
		return nil, nil
	}
	var msgs [][]byte
	for {
		idx := bytes.IndexByte(buf, 0)
		if idx < 0 {
			break
		}
		msgs = append(msgs, buf[:idx])
		buf = buf[idx+1:]
	}
	return msgs, buf
}

func mergePushReply(prev, next *PushReply) *PushReply {
	if next == nil {
		return prev
	}
	if prev == nil {
		return next
	}
	// Repeatable fields are appended in wire order (prev first, then next),
	// deduplicated, so continuation segments preserve their arrival order.
	next.Prefixes = appendUniquePrefixes(prev.Prefixes, next.Prefixes)
	next.Routes = appendUniquePrefixes(prev.Routes, next.Routes)
	next.DNS = appendUniqueAddrs(prev.DNS, next.DNS)
	nextHasPushReply := next.HasPushReply
	next.DataCiphers = appendUniqueStrings(prev.DataCiphers, next.DataCiphers)
	if next.PeerID == PeerIDUnset {
		next.PeerID = prev.PeerID
	}
	if next.Cipher == "" {
		next.Cipher = prev.Cipher
	}
	if !next.Redirect {
		next.Redirect = prev.Redirect
	}
	if !next.BlockIPv6 {
		next.BlockIPv6 = prev.BlockIPv6
	}
	if next.AuthTokenPass == "" {
		next.AuthTokenPass = prev.AuthTokenPass
	}
	if next.AuthTokenUser == "" {
		next.AuthTokenUser = prev.AuthTokenUser
	}
	// A deferred-auth timeout must survive merging into a later non-pending
	// PUSH_REPLY. Carry its observation-anchored deadline with the duration;
	// a genuinely later AUTH_PENDING keeps its own newly observed deadline.
	if !pushHasAuthPending(next) {
		next.AuthPendingTimeout = prev.AuthPendingTimeout
		next.authPendingUntil = prev.authPendingUntil
		next.hasAuthPending = prev.hasAuthPending
	}
	if !nextHasPushReply {
		next.PushContinuation = prev.PushContinuation
	}
	next.HasPushReply = next.HasPushReply || prev.HasPushReply
	return next
}

// appendUniquePrefixes returns prev followed by the elements of next that are
// not already present, preserving wire order (prev arrived first).
func appendUniquePrefixes(prev, next []netip.Prefix) []netip.Prefix {
	if len(prev) == 0 {
		return next
	}
	out := append([]netip.Prefix(nil), prev...)
	for _, p := range next {
		if !containsPrefix(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func containsPrefix(list []netip.Prefix, p netip.Prefix) bool {
	for _, q := range list {
		if q == p {
			return true
		}
	}
	return false
}

func appendUniqueAddrs(prev, next []netip.Addr) []netip.Addr {
	if len(prev) == 0 {
		return next
	}
	out := append([]netip.Addr(nil), prev...)
	for _, a := range next {
		if !containsAddr(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func containsAddr(list []netip.Addr, a netip.Addr) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func appendUniqueStrings(prev, next []string) []string {
	if len(prev) == 0 {
		return next
	}
	out := append([]string(nil), prev...)
	for _, s := range next {
		if !containsString(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, t := range list {
		if t == s {
			return true
		}
	}
	return false
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
