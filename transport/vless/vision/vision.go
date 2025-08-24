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
	"github.com/metacubex/mihomo/transport/vless/encryption"

	"github.com/gofrs/uuid/v5"
)

var ErrNotTLS13 = errors.New("XTLS Vision based on TLS 1.3 outer connection")

func NewConn(conn net.Conn, tlsConn net.Conn, userUUID *uuid.UUID) (*Conn, error) {
	c := &Conn{
		ExtendedReader:             N.NewExtendedReader(conn),
		ExtendedWriter:             N.NewExtendedWriter(conn),
		Conn:                       conn,
		userUUID:                   userUUID,
		tlsConn:                    tlsConn,
		packetsToFilter:            6,
		needHandshake:              true,
		readProcess:                true,
		readFilterUUID:             true,
		writeFilterApplicationData: true,
	}
	var t reflect.Type
	var p unsafe.Pointer
	switch underlying := tlsConn.(type) {
	case *gotls.Conn:
		//log.Debugln("type tls")
		c.netConn = underlying.NetConn()
		t = reflect.TypeOf(underlying).Elem()
		p = unsafe.Pointer(underlying)
	case *tlsC.Conn:
		//log.Debugln("type *tlsC.Conn")
		c.netConn = underlying.NetConn()
		t = reflect.TypeOf(underlying).Elem()
		p = unsafe.Pointer(underlying)
	case *tlsC.UConn:
		//log.Debugln("type *tlsC.UConn")
		c.netConn = underlying.NetConn()
		t = reflect.TypeOf(underlying.Conn).Elem()
		//log.Debugln("t:%v", t)
		p = unsafe.Pointer(underlying.Conn)
	case *encryption.CommonConn:
		//log.Debugln("type *encryption.CommonConn")
		c.netConn = underlying.Conn
		t = reflect.TypeOf(underlying).Elem()
		p = unsafe.Pointer(underlying)
	default:
		return nil, fmt.Errorf(`failed to use vision, maybe "security" is not "tls" or "utls"`)
	}
	if i, ok := t.FieldByName("input"); ok {
		c.input = (*bytes.Reader)(unsafe.Add(p, i.Offset))
	}
	if r, ok := t.FieldByName("rawInput"); ok {
		c.rawInput = (*bytes.Buffer)(unsafe.Add(p, r.Offset))
	}
	return c, nil
}

func (vc *Conn) checkTLSVersion() error {
	switch underlying := vc.tlsConn.(type) {
	case *gotls.Conn:
		if underlying.ConnectionState().Version != gotls.VersionTLS13 {
			return ErrNotTLS13
		}
	case *tlsC.Conn:
		if underlying.ConnectionState().Version != tlsC.VersionTLS13 {
			return ErrNotTLS13
		}
	case *tlsC.UConn:
		if underlying.ConnectionState().Version != tlsC.VersionTLS13 {
			return ErrNotTLS13
		}
	}
	return nil
}
