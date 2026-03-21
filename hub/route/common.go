package route

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

// When name is composed of a partial escape string, Golang does not unescape it
func getEscapeParam(r *http.Request, paramName string) string {
	param := chi.URLParam(r, paramName)
	if newParam, err := url.PathUnescape(param); err == nil {
		param = newParam
	}
	return param
}

// wsUpgrade upgrades http connection to the websocket connection.
//
// It hijacks net.Conn from w and returns received net.Conn and
// bufio.ReadWriter.
func wsUpgrade(r *http.Request, w http.ResponseWriter) (conn net.Conn, rw *bufio.ReadWriter, err error) {
	// See https://tools.ietf.org/html/rfc6455#section-4.1
	// The method of the request MUST be GET, and the HTTP version MUST be at least 1.1.
	var nonce string
	if r.Method != http.MethodGet {
		err = errors.New("handshake error: bad HTTP request method")
		body := err.Error()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(body))
		return nil, nil, err
	} else if r.ProtoMajor < 1 || (r.ProtoMajor == 1 && r.ProtoMinor < 1) {
		err = errors.New("handshake error: bad HTTP protocol version")
		body := err.Error()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusHTTPVersionNotSupported)
		w.Write([]byte(body))
		return nil, nil, err
	} else if r.Host == "" {
		err = errors.New("handshake error: bad Host header")
		body := err.Error()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(body))
		return nil, nil, err
	} else if u := r.Header.Get("Upgrade"); u != "websocket" && !strings.EqualFold(u, "websocket") {
		err = errors.New("handshake error: bad Upgrade header")
		body := err.Error()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(body))
		return nil, nil, err
	} else if c := r.Header.Get("Connection"); c != "Upgrade" && !strings.Contains(strings.ToLower(c), "upgrade") {
		err = errors.New("handshake error: bad Connection header")
		body := err.Error()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(body))
		return nil, nil, err
	} else if nonce = r.Header.Get("Sec-WebSocket-Key"); len(nonce) != 24 {
		err = errors.New("handshake error: bad Sec-WebSocket-Key header")
		body := err.Error()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(body))
		return nil, nil, err
	} else if v := r.Header.Get("Sec-WebSocket-Version"); v != "13" {
		err = errors.New("handshake error: bad Sec-WebSocket-Version header")
		body := err.Error()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if v != "" {
			// According to RFC6455:
			// If this version does not match a version understood by the server, the
			// server MUST abort the WebSocket handshake described in this section and
			// instead send an appropriate HTTP error code (such as 426 Upgrade Required)
			// and a |Sec-WebSocket-Version| header field indicating the version(s) the
			// server is capable of understanding.
			w.Header().Set("Sec-WebSocket-Version", "13")
			w.WriteHeader(http.StatusUpgradeRequired)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		w.Write([]byte(body))
		return nil, nil, err
	}

	conn, rw, err = http.NewResponseController(w).Hijack()
	if err != nil {
		body := err.Error()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(body))
		return nil, nil, err
	}

	// Clear deadlines set by server.
	conn.SetDeadline(time.Time{})

	rw.Writer.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	header := http.Header{}
	header.Set("Upgrade", "websocket")
	header.Set("Connection", "Upgrade")
	header.Set("Sec-WebSocket-Accept", N.GetWebSocketSecAccept(nonce))
	header.Write(rw.Writer)
	rw.Writer.WriteString("\r\n")
	err = rw.Writer.Flush()

	return conn, rw, err
}

// wsWriteServerMessage writes message to w, considering that caller represents server side.
func wsWriteServerMessage(w io.Writer, op byte, p []byte) error {
	dataLen := len(p)

	// Make slice of bytes with capacity 14 that could hold any header.
	bts := make([]byte, 14)

	bts[0] |= 0x80   //FIN
	bts[0] |= 0 << 4 //RSV
	bts[0] |= op     //OPCODE

	var n int
	switch {
	case dataLen < 126:
		bts[1] = byte(dataLen)
		n = 2
	case dataLen < 65536:
		bts[1] = 126
		binary.BigEndian.PutUint16(bts[2:4], uint16(dataLen))
		n = 4
	default:
		bts[1] = 127
		binary.BigEndian.PutUint64(bts[2:10], uint64(dataLen))
		n = 10
	}

	_, err := w.Write(bts[:n])
	if err != nil {
		return err
	}
	_, err = w.Write(p)
	return err
}

// wsWriteServerText is the same as wsWriteServerMessage with ws.OpText.
func wsWriteServerText(w io.Writer, p []byte) error {
	const opText = 0x1
	return wsWriteServerMessage(w, opText, p)
}

// wsWriteServerBinary is the same as wsWriteServerMessage with ws.OpBinary.
func wsWriteServerBinary(w io.Writer, p []byte) error {
	const opBinary = 0x2
	return wsWriteServerMessage(w, opBinary, p)
}
