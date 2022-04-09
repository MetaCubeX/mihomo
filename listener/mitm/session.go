package mitm

import (
	"fmt"
	"io"
	"net"
	"net/http"

	C "github.com/Dreamacro/clash/constant"
)

var serverName = fmt.Sprintf("Clash server (%s)", C.Version)

type Session struct {
	conn     net.Conn
	request  *http.Request
	response *http.Response

	props map[string]any
}

func (s *Session) Request() *http.Request {
	return s.request
}

func (s *Session) Response() *http.Response {
	return s.response
}

func (s *Session) GetProperties(key string) (any, bool) {
	v, ok := s.props[key]
	return v, ok
}

func (s *Session) SetProperties(key string, val any) {
	s.props[key] = val
}

func (s *Session) NewResponse(code int, body io.Reader) *http.Response {
	res := NewResponse(code, body, s.request)
	res.Header.Set("Server", serverName)
	return res
}

func (s *Session) NewErrorResponse(err error) *http.Response {
	return NewErrorResponse(s.request, err)
}

func NewSession(conn net.Conn, request *http.Request, response *http.Response) *Session {
	return &Session{
		conn:     conn,
		request:  request,
		response: response,
		props:    map[string]any{},
	}
}
