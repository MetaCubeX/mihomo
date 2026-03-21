package gun

import (
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/metacubex/http"
)

type clientConnPool struct {
	t *http.Http2Transport

	mu           sync.Mutex
	conns        map[string][]*http.Http2ClientConn // key is host:port
	dialing      map[string]unsafe.Pointer          // currently in-flight dials
	keys         map[*http.Http2ClientConn][]string
	addConnCalls map[string]unsafe.Pointer // in-flight addConnIfNeeded calls
}

type clientConn struct {
	t     *http.Transport
	tconn net.Conn // usually *tls.Conn, except specialized impls
}

type efaceWords struct {
	typ  unsafe.Pointer
	data unsafe.Pointer
}

type tlsConn interface {
	net.Conn
	NetConn() net.Conn
}

func closeClientConn(cc *http.Http2ClientConn) { // like forceCloseConn() in http.Http2ClientConn but also apply for tls-like conn
	if conn, ok := (*clientConn)(unsafe.Pointer(cc)).tconn.(tlsConn); ok {
		t := time.AfterFunc(time.Second, func() {
			_ = conn.NetConn().Close()
		})
		defer t.Stop()
	}
	_ = cc.Close()
}

func CloseTransport(tr *http.Http2Transport) {
	connPool := transportConnPool(tr)
	p := (*clientConnPool)((*efaceWords)(unsafe.Pointer(&connPool)).data)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, vv := range p.conns {
		for _, cc := range vv {
			closeClientConn(cc)
		}
	}
	// cleanup
	p.conns = make(map[string][]*http.Http2ClientConn)
	p.keys = make(map[*http.Http2ClientConn][]string)
}

//go:linkname transportConnPool github.com/metacubex/http.(*http2Transport).connPool
func transportConnPool(t *http.Http2Transport) http.Http2ClientConnPool
