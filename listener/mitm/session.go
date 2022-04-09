package mitm

import (
	"io"
	"net"
	"net/http"
)

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
	return NewResponse(code, body, s.request)
}

func (s *Session) NewErrorResponse(err error) *http.Response {
	return NewErrorResponse(s.request, err)
}

func (s *Session) writeResponse() error {
	if s.response == nil {
		return ErrInvalidResponse
	}
	defer func(resp *http.Response) {
		_ = resp.Body.Close()
	}(s.response)
	return s.response.Write(s.conn)
}

func newSession(conn net.Conn, request *http.Request, response *http.Response) *Session {
	return &Session{
		conn:     conn,
		request:  request,
		response: response,
		props:    map[string]any{},
	}
}
