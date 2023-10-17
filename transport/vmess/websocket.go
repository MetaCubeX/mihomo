package vmess

import (
	"bufio"
	"bytes"
	"context"
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

	"github.com/Dreamacro/clash/common/buf"
	N "github.com/Dreamacro/clash/common/net"
	tlsC "github.com/Dreamacro/clash/component/tls"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/zhangyunhao116/fastrand"
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
	Host                string
	Port                string
	Path                string
	Headers             http.Header
	TLS                 bool
	TLSConfig           *tls.Config
	MaxEarlyData        int
	EarlyDataHeaderName string
	ClientFingerprint   string
}

// Read implements net.Conn.Read()
// modify from gobwas/ws/wsutil.readData
func (wsc *websocketConn) Read(b []byte) (n int, err error) {
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
		maskKey := fastrand.Uint32()
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
	dialer := ws.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
		TLSConfig: c.TLSConfig,
	}
	scheme := "ws"
	if c.TLS {
		scheme = "wss"
		if len(c.ClientFingerprint) != 0 {
			if fingerprint, exists := tlsC.GetFingerprint(c.ClientFingerprint); exists {
				utlsConn := tlsC.UClient(conn, c.TLSConfig, fingerprint)

				if err := utlsConn.(*tlsC.UConn).BuildWebsocketHandshakeState(); err != nil {
					return nil, fmt.Errorf("parse url %s error: %w", c.Path, err)
				}

				dialer.TLSClient = func(conn net.Conn, hostname string) net.Conn {
					return utlsConn
				}
			}
		}
	}

	u, err := url.Parse(c.Path)
	if err != nil {
		return nil, fmt.Errorf("parse url %s error: %w", c.Path, err)
	}

	uri := url.URL{
		Scheme:   scheme,
		Host:     net.JoinHostPort(c.Host, c.Port),
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}

	headers := http.Header{}
	headers.Set("User-Agent", "Go-http-client/1.1") // match golang's net/http
	if c.Headers != nil {
		for k := range c.Headers {
			headers.Add(k, c.Headers.Get(k))
		}
	}

	if earlyData != nil {
		earlyDataString := earlyData.String()
		if c.EarlyDataHeaderName == "" {
			uri.Path += earlyDataString
		} else {
			headers.Set(c.EarlyDataHeaderName, earlyDataString)
		}
	}

	// gobwas/ws will check server's response "Sec-Websocket-Protocol" so must add Protocols to ws.Dialer
	// if not will cause ws.ErrHandshakeBadSubProtocol
	if secProtocol := headers.Get("Sec-WebSocket-Protocol"); len(secProtocol) > 0 {
		// gobwas/ws will set "Sec-Websocket-Protocol" according dialer.Protocols
		// to avoid send repeatedly don't set it to headers
		headers.Del("Sec-WebSocket-Protocol")
		dialer.Protocols = []string{secProtocol}
	}

	// gobwas/ws send "Host" directly in Upgrade() by `httpWriteHeader(bw, headerHost, u.Host)`
	// if headers has "Host" will send repeatedly
	if host := headers.Get("Host"); host != "" {
		headers.Del("Host")
		uri.Host = host
	}

	dialer.Header = ws.HandshakeHeaderHTTP(headers)

	conn, reader, _, err := dialer.Dial(ctx, uri.String())
	if err != nil {
		return nil, fmt.Errorf("dial %s error: %w", uri.Host, err)
	}

	conn = newWebsocketConn(conn, reader, ws.StateClientSide)
	// websocketConn can't correct handle ReadDeadline
	// so call N.NewDeadlineConn to add a safe wrapper
	return N.NewDeadlineConn(conn), nil
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

func newWebsocketConn(conn net.Conn, br *bufio.Reader, state ws.State) *websocketConn {
	controlHandler := wsutil.ControlFrameHandler(conn, state)
	var reader io.Reader
	if br != nil && br.Buffered() > 0 {
		reader = br
	} else {
		reader = conn
	}
	return &websocketConn{
		Conn:  conn,
		state: state,
		reader: &wsutil.Reader{
			Source:          reader,
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

func StreamUpgradedWebsocketConn(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	wsConn, rw, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		return nil, err
	}
	conn := newWebsocketConn(wsConn, rw.Reader, ws.StateServerSide)
	if edBuf := decodeXray0rtt(r.Header); len(edBuf) > 0 {
		return N.NewDeadlineConn(&websocketWithReaderConn{conn, io.MultiReader(bytes.NewReader(edBuf), conn)}), nil
	}
	return N.NewDeadlineConn(conn), nil
}

type websocketWithReaderConn struct {
	*websocketConn
	reader io.Reader
}

func (ws *websocketWithReaderConn) Read(b []byte) (n int, err error) {
	return ws.reader.Read(b)
}
