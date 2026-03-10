package httpmask

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gobwas/ws"
)

func looksLikeWebSocketUpgrade(headers map[string]string) bool {
	if headers == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(headers["upgrade"]), "websocket") {
		return false
	}
	conn := headers["connection"]
	for _, part := range strings.Split(conn, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
			return true
		}
	}
	return false
}

func (s *TunnelServer) handleWS(rawConn net.Conn, req *httpRequestHeader, headerBytes []byte, buffered []byte) (HandleResult, net.Conn, error) {
	rejectOrReply := func(code int, body string) (HandleResult, net.Conn, error) {
		if s.passThroughOnReject {
			prefix := make([]byte, 0, len(headerBytes)+len(buffered))
			prefix = append(prefix, headerBytes...)
			prefix = append(prefix, buffered...)
			return HandlePassThrough, newRejectedPreBufferedConn(rawConn, prefix), nil
		}
		_ = writeSimpleHTTPResponse(rawConn, code, body)
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	u, err := url.ParseRequestURI(req.target)
	if err != nil {
		return rejectOrReply(http.StatusBadRequest, "bad request")
	}

	path, ok := stripPathRoot(s.pathRoot, u.Path)
	if !ok || path != "/ws" {
		return rejectOrReply(http.StatusNotFound, "not found")
	}
	if strings.ToUpper(strings.TrimSpace(req.method)) != http.MethodGet {
		return rejectOrReply(http.StatusBadRequest, "bad request")
	}
	if !looksLikeWebSocketUpgrade(req.headers) {
		return rejectOrReply(http.StatusBadRequest, "bad request")
	}

	authVal := req.headers["authorization"]
	if authVal == "" {
		authVal = u.Query().Get(tunnelAuthQueryKey)
	}
	if !s.auth.verifyValue(authVal, TunnelModeWS, req.method, path, time.Now()) {
		return rejectOrReply(http.StatusNotFound, "not found")
	}

	earlyPayload, err := parseEarlyDataQuery(u)
	if err != nil {
		return rejectOrReply(http.StatusBadRequest, "bad request")
	}
	var prepared *PreparedServerEarlyHandshake
	if len(earlyPayload) > 0 && s.earlyHandshake != nil && s.earlyHandshake.Prepare != nil {
		prepared, err = s.earlyHandshake.Prepare(earlyPayload)
		if err != nil {
			return rejectOrReply(http.StatusNotFound, "not found")
		}
	}

	prefix := make([]byte, 0, len(headerBytes)+len(buffered))
	prefix = append(prefix, headerBytes...)
	prefix = append(prefix, buffered...)
	wsConnRaw := newPreBufferedConn(rawConn, prefix)

	upgrader := ws.Upgrader{}
	if prepared != nil && len(prepared.ResponsePayload) > 0 {
		upgrader.OnBeforeUpgrade = func() (ws.HandshakeHeader, error) {
			h := http.Header{}
			h.Set(tunnelEarlyDataHeader, base64.RawURLEncoding.EncodeToString(prepared.ResponsePayload))
			return ws.HandshakeHeaderHTTP(h), nil
		}
	}
	if _, err := upgrader.Upgrade(wsConnRaw); err != nil {
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	outConn := net.Conn(newWSStreamConn(wsConnRaw, ws.StateServerSide))
	if prepared != nil && prepared.WrapConn != nil {
		wrapped, err := prepared.WrapConn(outConn)
		if err != nil {
			_ = outConn.Close()
			return HandleDone, nil, nil
		}
		if wrapped != nil {
			outConn = wrapEarlyHandshakeConn(wrapped, prepared.UserHash)
		}
	}
	return HandleStartTunnel, outConn, nil
}
