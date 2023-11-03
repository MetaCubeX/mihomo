// Package vision implements VLESS flow `xtls-rprx-vision` introduced by Xray-core.
package vision

import (
	"bytes"
	gotls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"unsafe"

	N "github.com/metacubex/mihomo/common/net"
	tlsC "github.com/metacubex/mihomo/component/tls"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing/common"
	utls "github.com/sagernet/utls"
)

var ErrNotTLS13 = errors.New("XTLS Vision based on TLS 1.3 outer connection")

type connWithUpstream interface {
	net.Conn
	common.WithUpstream
}

func NewConn(conn connWithUpstream, userUUID *uuid.UUID) (*Conn, error) {
	c := &Conn{
		ExtendedReader:             N.NewExtendedReader(conn),
		ExtendedWriter:             N.NewExtendedWriter(conn),
		upstream:                   conn,
		userUUID:                   userUUID,
		packetsToFilter:            6,
		needHandshake:              true,
		readProcess:                true,
		readFilterUUID:             true,
		writeFilterApplicationData: true,
	}
	var t reflect.Type
	var p unsafe.Pointer
	switch underlying := conn.Upstream().(type) {
	case *gotls.Conn:
		//log.Debugln("type tls")
		c.Conn = underlying.NetConn()
		c.tlsConn = underlying
		t = reflect.TypeOf(underlying).Elem()
		p = unsafe.Pointer(underlying)
	case *utls.UConn:
		//log.Debugln("type *utls.UConn")
		c.Conn = underlying.NetConn()
		c.tlsConn = underlying
		t = reflect.TypeOf(underlying.Conn).Elem()
		p = unsafe.Pointer(underlying.Conn)
	case *tlsC.UConn:
		//log.Debugln("type *tlsC.UConn")
		c.Conn = underlying.NetConn()
		c.tlsConn = underlying.UConn
		t = reflect.TypeOf(underlying.Conn).Elem()
		//log.Debugln("t:%v", t)
		p = unsafe.Pointer(underlying.Conn)
	default:
		return nil, fmt.Errorf(`failed to use vision, maybe "security" is not "tls" or "utls"`)
	}
	i, _ := t.FieldByName("input")
	r, _ := t.FieldByName("rawInput")
	c.input = (*bytes.Reader)(unsafe.Add(p, i.Offset))
	c.rawInput = (*bytes.Buffer)(unsafe.Add(p, r.Offset))
	return c, nil
}
