package context

import (
	"net"
	"net/http"

	C "github.com/Dreamacro/clash/constant"

	"github.com/gofrs/uuid"
)

type HTTPContext struct {
	id       uuid.UUID
	metadata *C.Metadata
	conn     net.Conn
	req      *http.Request
}

func NewHTTPContext(conn net.Conn, req *http.Request, metadata *C.Metadata) *HTTPContext {
	id, _ := uuid.NewV4()
	return &HTTPContext{
		id:       id,
		metadata: metadata,
		conn:     conn,
		req:      req,
	}
}

// ID implement C.ConnContext ID
func (hc *HTTPContext) ID() uuid.UUID {
	return hc.id
}

// Metadata implement C.ConnContext Metadata
func (hc *HTTPContext) Metadata() *C.Metadata {
	return hc.metadata
}

// Conn implement C.ConnContext Conn
func (hc *HTTPContext) Conn() net.Conn {
	return hc.conn
}

// Request return the http request struct
func (hc *HTTPContext) Request() *http.Request {
	return hc.req
}
