package vmess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/log"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/metacubex/randv2"
)

type websocketConn struct {
	net.Conn
	state          ws.State
	reader         *wsutil.Reader
	controlHandler wsutil.FrameHandlerFunc

	rawWriter N.ExtendedWriter
}

type websocketWithEarlyDataConn struct {
	net.Conn
	wsWriter N.ExtendedWriter
	underlay net.Conn
	closed   bool
	dialed   chan bool
	cancel   context.CancelFunc
	ctx      context.Context
	config   *WebsocketConfig
}

type WebsocketConfig struct {
	Host                     string
	Port                     string
	Path                     string
	Headers                  http.Header
	TLS                      bool
	TLSConfig                *tls.Config
	MaxEarlyData             int
	EarlyDataHeaderName      string
	ClientFingerprint        string
	V2rayHttpUpgrade         bool
	V2rayHttpUpgradeFastOpen bool
}

// Read implements net.Conn.Read()
// modify from gobwas/ws/wsutil.readData
func (wsc *websocketConn) Read(b []byte) (n int, err error) {
	defer func() { // avoid gobwas/ws pbytes.GetLen panic
		if value := recover(); value != nil {
			err = fmt.Errorf("websocket error: %s", value)
		}
	}()
	var header ws.Header
	for {
		n, err = wsc.reader.Read(b)
		// in gobwas/ws: "The error is io.EOF only if all of message bytes were read."
		// but maybe next frame still have data, so drop it
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if !errors.Is(err, wsutil.ErrNoFrameAdvance) {
			return
		}
		header, err = wsc.reader.NextFrame()
		if err != nil {
			return
		}
		if header.OpCode.IsControl() {
			err = wsc.controlHandler(header, wsc.reader)
			if err != nil {
				return
			}
			continue
		}
		if header.OpCode&(ws.OpBinary|ws.OpText) == 0 {
			err = wsc.reader.Discard()
			if err != nil {
				return
			}
			continue
		}
	}
}

// Write implements io.Writer.
func (wsc *websocketConn) Write(b []byte) (n int, err error) {
	err = wsutil.WriteMessage(wsc.Conn, wsc.state, ws.OpBinary, b)
	if err != nil {
		return
	}
	n = len(b)
	return
}

func (wsc *websocketConn) WriteBuffer(buffer *buf.Buffer) error {
	var payloadBitLength int
	dataLen := buffer.Len()
	data := buffer.Bytes()
	if dataLen < 126 {
		payloadBitLength = 1
	} else if dataLen < 65536 {
		payloadBitLength = 3
	} else {
		payloadBitLength = 9
	}

	var headerLen int
	headerLen += 1 // FIN / RSV / OPCODE
	headerLen += payloadBitLength
	if wsc.state.ClientSide() {
		headerLen += 4 // MASK KEY
	}

	header := buffer.ExtendHeader(headerLen)
	header[0] = byte(ws.OpBinary) | 0x80
	if wsc.state.ClientSide() {
		header[1] = 1 << 7
	} else {
		header[1] = 0
	}

	if dataLen < 126 {
		header[1] |= byte(dataLen)
	} else if dataLen < 65536 {
		header[1] |= 126
		binary.BigEndian.PutUint16(header[2:], uint16(dataLen))
	} else {
		header[1] |= 127
		binary.BigEndian.PutUint64(header[2:], uint64(dataLen))
	}

	if wsc.state.ClientSide() {
		maskKey := randv2.Uint32()
		binary.LittleEndian.PutUint32(header[1+payloadBitLength:], maskKey)
		N.MaskWebSocket(maskKey, data)
	}

	return wsc.rawWriter.WriteBuffer(buffer)
}

func (wsc *websocketConn) FrontHeadroom() int {
	return 14
}

func (wsc *websocketConn) Upstream() any {
	return wsc.Conn
}

func (wsc *websocketConn) Close() error {
	_ = wsc.Conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
	_ = wsutil.WriteMessage(wsc.Conn, wsc.state, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, ""))
	_ = wsc.Conn.Close()
	return nil
}

func (wsedc *websocketWithEarlyDataConn) Dial(earlyData []byte) error {
	base64DataBuf := &bytes.Buffer{}
	base64EarlyDataEncoder := base64.NewEncoder(base64.RawURLEncoding, base64DataBuf)

	earlyDataBuf := bytes.NewBuffer(earlyData)
	if _, err := base64EarlyDataEncoder.Write(earlyDataBuf.Next(wsedc.config.MaxEarlyData)); err != nil {
		return fmt.Errorf("failed to encode early data: %w", err)
	}

	if errc := base64EarlyDataEncoder.Close(); errc != nil {
		return fmt.Errorf("failed to encode early data tail: %w", errc)
	}

	var err error
	if wsedc.Conn, err = streamWebsocketConn(wsedc.ctx, wsedc.underlay, wsedc.config, base64DataBuf); err != nil {
		wsedc.Close()
		return fmt.Errorf("failed to dial WebSocket: %w", err)
	}

	wsedc.dialed <- true
	wsedc.wsWriter = N.NewExtendedWriter(wsedc.Conn)
	if earlyDataBuf.Len() != 0 {
		_, err = wsedc.Conn.Write(earlyDataBuf.Bytes())
	}

	return err
}

func (wsedc *websocketWithEarlyDataConn) Write(b []byte) (int, error) {
	if wsedc.closed {
		return 0, io.ErrClosedPipe
	}
	if wsedc.Conn == nil {
		if err := wsedc.Dial(b); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	return wsedc.Conn.Write(b)
}

func (wsedc *websocketWithEarlyDataConn) WriteBuffer(buffer *buf.Buffer) error {
	if wsedc.closed {
		return io.ErrClosedPipe
	}
	if wsedc.Conn == nil {
		if err := wsedc.Dial(buffer.Bytes()); err != nil {
			return err
		}
		return nil
	}

	return wsedc.wsWriter.WriteBuffer(buffer)
}

func (wsedc *websocketWithEarlyDataConn) Read(b []byte) (int, error) {
	if wsedc.closed {
		return 0, io.ErrClosedPipe
	}
	if wsedc.Conn == nil {
		select {
		case <-wsedc.ctx.Done():
			return 0, io.ErrUnexpectedEOF
		case <-wsedc.dialed:
		}
	}
	return wsedc.Conn.Read(b)
}

func (wsedc *websocketWithEarlyDataConn) Close() error {
	wsedc.closed = true
	wsedc.cancel()
	if wsedc.Conn == nil {
		return nil
	}
	return wsedc.Conn.Close()
}

func (wsedc *websocketWithEarlyDataConn) LocalAddr() net.Addr {
	if wsedc.Conn == nil {
		return wsedc.underlay.LocalAddr()
	}
	return wsedc.Conn.LocalAddr()
}

func (wsedc *websocketWithEarlyDataConn) RemoteAddr() net.Addr {
	if wsedc.Conn == nil {
		return wsedc.underlay.RemoteAddr()
	}
	return wsedc.Conn.RemoteAddr()
}

func (wsedc *websocketWithEarlyDataConn) SetDeadline(t time.Time) error {
	if err := wsedc.SetReadDeadline(t); err != nil {
		return err
	}
	return wsedc.SetWriteDeadline(t)
}

func (wsedc *websocketWithEarlyDataConn) SetReadDeadline(t time.Time) error {
	if wsedc.Conn == nil {
		return nil
	}
	return wsedc.Conn.SetReadDeadline(t)
}

func (wsedc *websocketWithEarlyDataConn) SetWriteDeadline(t time.Time) error {
	if wsedc.Conn == nil {
		return nil
	}
	return wsedc.Conn.SetWriteDeadline(t)
}

func (wsedc *websocketWithEarlyDataConn) FrontHeadroom() int {
	return 14
}

func (wsedc *websocketWithEarlyDataConn) Upstream() any {
	return wsedc.underlay
}

//func (wsedc *websocketWithEarlyDataConn) LazyHeadroom() bool {
//	return wsedc.Conn == nil
//}
//
//func (wsedc *websocketWithEarlyDataConn) Upstream() any {
//	if wsedc.Conn == nil { // ensure return a nil interface not an interface with nil value
//		return nil
//	}
//	return wsedc.Conn
//}

func (wsedc *websocketWithEarlyDataConn) NeedHandshake() bool {
	return wsedc.Conn == nil
}

func streamWebsocketWithEarlyDataConn(conn net.Conn, c *WebsocketConfig) (net.Conn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	conn = &websocketWithEarlyDataConn{
		dialed:   make(chan bool, 1),
		cancel:   cancel,
		ctx:      ctx,
		underlay: conn,
		config:   c,
	}
	// websocketWithEarlyDataConn can't correct handle Deadline
	// it will not apply the already set Deadline after Dial()
	// so call N.NewDeadlineConn to add a safe wrapper
	return N.NewDeadlineConn(conn), nil
}

func streamWebsocketConn(ctx context.Context, conn net.Conn, c *WebsocketConfig, earlyData *bytes.Buffer) (net.Conn, error) {
	u, err := url.Parse(c.Path)
	if err != nil {
		return nil, fmt.Errorf("parse url %s error: %w", c.Path, err)
	}

	uri := url.URL{
		Scheme:   "ws",
		Host:     net.JoinHostPort(c.Host, c.Port),
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}

	if !strings.HasPrefix(uri.Path, "/") {
		uri.Path = "/" + uri.Path
	}

	if c.TLS {
		uri.Scheme = "wss"
		config := c.TLSConfig
		if config == nil { // The config cannot be nil
			config = &tls.Config{NextProtos: []string{"http/1.1"}}
		}
		if config.ServerName == "" && !config.InsecureSkipVerify { // users must set either ServerName or InsecureSkipVerify in the config.
			config = config.Clone()
			config.ServerName = uri.Host
		}

		if len(c.ClientFingerprint) != 0 {
			if fingerprint, exists := tlsC.GetFingerprint(c.ClientFingerprint); exists {
				utlsConn := tlsC.UClient(conn, config, fingerprint)
				if err = utlsConn.BuildWebsocketHandshakeState(); err != nil {
					return nil, fmt.Errorf("parse url %s error: %w", c.Path, err)
				}
				conn = utlsConn
			}
		} else {
			conn = tls.Client(conn, config)
		}

		if tlsConn, ok := conn.(interface {
			HandshakeContext(ctx context.Context) error
		}); ok {
			if err = tlsConn.HandshakeContext(ctx); err != nil {
				return nil, err
			}
		}
	}

	request := &http.Request{
		Method: http.MethodGet,
		URL:    &uri,
		Header: c.Headers.Clone(),
		Host:   c.Host,
	}

	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")

	if host := request.Header.Get("Host"); host != "" {
		// For client requests, Host optionally overrides the Host
		// header to send. If empty, the Request.Write method uses
		// the value of URL.Host. Host may contain an international
		// domain name.
		request.Host = host
	}
	request.Header.Del("Host")

	var secKey string
	if !c.V2rayHttpUpgrade {
		const nonceKeySize = 16
		// NOTE: bts does not escape.
		bts := make([]byte, nonceKeySize)
		if _, err = rand.Read(bts); err != nil {
			return nil, fmt.Errorf("rand read error: %w", err)
		}
		secKey = base64.StdEncoding.EncodeToString(bts)
		request.Header.Set("Sec-WebSocket-Version", "13")
		request.Header.Set("Sec-WebSocket-Key", secKey)
	}

	if earlyData != nil {
		earlyDataString := earlyData.String()
		if c.EarlyDataHeaderName == "" {
			uri.Path += earlyDataString
		} else {
			request.Header.Set(c.EarlyDataHeaderName, earlyDataString)
		}
	}

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
	}

	err = request.Write(conn)
	if err != nil {
		return nil, err
	}
	bufferedConn := N.NewBufferedConn(conn)

	if c.V2rayHttpUpgrade && c.V2rayHttpUpgradeFastOpen {
		return N.NewEarlyConn(bufferedConn, func() error {
			response, err := http.ReadResponse(bufferedConn.Reader(), request)
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusSwitchingProtocols ||
				!strings.EqualFold(response.Header.Get("Connection"), "upgrade") ||
				!strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
				return fmt.Errorf("unexpected status: %s", response.Status)
			}
			return nil
		}), nil
	}

	response, err := http.ReadResponse(bufferedConn.Reader(), request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(response.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("unexpected status: %s", response.Status)
	}

	if c.V2rayHttpUpgrade {
		return bufferedConn, nil
	}

	if log.Level() == log.DEBUG { // we might not check this for performance
		secAccept := response.Header.Get("Sec-Websocket-Accept")
		const acceptSize = 28 // base64.StdEncoding.EncodedLen(sha1.Size)
		if lenSecAccept := len(secAccept); lenSecAccept != acceptSize {
			return nil, fmt.Errorf("unexpected Sec-Websocket-Accept length: %d", lenSecAccept)
		}
		if getSecAccept(secKey) != secAccept {
			return nil, errors.New("unexpected Sec-Websocket-Accept")
		}
	}

	conn = newWebsocketConn(conn, ws.StateClientSide)
	// websocketConn can't correct handle ReadDeadline
	// so call N.NewDeadlineConn to add a safe wrapper
	return N.NewDeadlineConn(conn), nil
}

func getSecAccept(secKey string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	const nonceSize = 24 // base64.StdEncoding.EncodedLen(nonceKeySize)
	p := make([]byte, nonceSize+len(magic))
	copy(p[:nonceSize], secKey)
	copy(p[nonceSize:], magic)
	sum := sha1.Sum(p)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func StreamWebsocketConn(ctx context.Context, conn net.Conn, c *WebsocketConfig) (net.Conn, error) {
	if u, err := url.Parse(c.Path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			if ed, err := strconv.Atoi(q.Get("ed")); err == nil {
				c.MaxEarlyData = ed
				c.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
				q.Del("ed")
				u.RawQuery = q.Encode()
				c.Path = u.String()
			}
		}
	}

	if c.MaxEarlyData > 0 {
		return streamWebsocketWithEarlyDataConn(conn, c)
	}

	return streamWebsocketConn(ctx, conn, c, nil)
}

func newWebsocketConn(conn net.Conn, state ws.State) *websocketConn {
	controlHandler := wsutil.ControlFrameHandler(conn, state)
	return &websocketConn{
		Conn:  conn,
		state: state,
		reader: &wsutil.Reader{
			Source:          conn,
			State:           state,
			SkipHeaderCheck: true,
			CheckUTF8:       false,
			OnIntermediate:  controlHandler,
		},
		controlHandler: controlHandler,
		rawWriter:      N.NewExtendedWriter(conn),
	}
}

var replacer = strings.NewReplacer("+", "-", "/", "_", "=", "")

func decodeEd(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(replacer.Replace(s))
}

func decodeXray0rtt(requestHeader http.Header) []byte {
	// read inHeader's `Sec-WebSocket-Protocol` for Xray's 0rtt ws
	if secProtocol := requestHeader.Get("Sec-WebSocket-Protocol"); len(secProtocol) > 0 {
		if edBuf, err := decodeEd(secProtocol); err == nil { // sure could base64 decode
			return edBuf
		}
	}
	return nil
}

func IsWebSocketUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") == "websocket"
}

func IsV2rayHttpUpdate(r *http.Request) bool {
	return IsWebSocketUpgrade(r) && r.Header.Get("Sec-WebSocket-Key") == ""
}

func StreamUpgradedWebsocketConn(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	var conn net.Conn
	var rw *bufio.ReadWriter
	var err error
	isRaw := IsV2rayHttpUpdate(r)
	w.Header().Set("Connection", "upgrade")
	w.Header().Set("Upgrade", "websocket")
	if !isRaw {
		w.Header().Set("Sec-Websocket-Accept", getSecAccept(r.Header.Get("Sec-WebSocket-Key")))
	}
	w.WriteHeader(http.StatusSwitchingProtocols)
	if flusher, isFlusher := w.(interface{ FlushError() error }); isFlusher {
		err = flusher.FlushError()
		if err != nil {
			return nil, fmt.Errorf("flush response: %w", err)
		}
	}
	hijacker, canHijack := w.(http.Hijacker)
	if !canHijack {
		return nil, errors.New("invalid connection, maybe HTTP/2")
	}
	conn, rw, err = hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack failed: %w", err)
	}

	// rw.Writer was flushed, so we only need warp rw.Reader
	conn = N.WarpConnWithBioReader(conn, rw.Reader)

	if !isRaw {
		conn = newWebsocketConn(conn, ws.StateServerSide)
		// websocketConn can't correct handle ReadDeadline
		// so call N.NewDeadlineConn to add a safe wrapper
		conn = N.NewDeadlineConn(conn)
	}

	if edBuf := decodeXray0rtt(r.Header); len(edBuf) > 0 {
		appendOk := false
		if bufConn, ok := conn.(*N.BufferedConn); ok {
			appendOk = bufConn.AppendData(edBuf)
		}
		if !appendOk {
			conn = N.NewCachedConn(conn, edBuf)
		}

	}

	return conn, nil
}
