// Package vision implements VLESS flow `xtls-rprx-vision` introduced by Xray-core.
//
// same logic as https://github.com/XTLS/Xray-core/blob/v25.9.11/proxy/proxy.go
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
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vless/encryption"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/tls"
)

var ErrNotHandshakeComplete = errors.New("tls connection not handshake complete")
var ErrNotTLS13 = errors.New("XTLS Vision based on TLS 1.3 outer connection")

func NewConn(conn net.Conn, tlsConn net.Conn, userUUID uuid.UUID) (*Conn, error) {
	c := &Conn{
		ExtendedReader:             N.NewExtendedReader(conn),
		ExtendedWriter:             N.NewExtendedWriter(conn),
		Conn:                       conn,
		userUUID:                   userUUID,
		packetsToFilter:            8,
		readProcess:                true,
		readFilterUUID:             true,
		writeFilterApplicationData: true,
		writeOnceUserUUID:          userUUID.Bytes(),
	}
	var t reflect.Type
	var p unsafe.Pointer
	var upstream any = tlsConn
	for {
		switch underlying := upstream.(type) {
		case *gotls.Conn:
			//log.Debugln("type tls")
			tlsConn = underlying
			c.netConn = underlying.NetConn()
			t = reflect.TypeOf(underlying).Elem()
			p = unsafe.Pointer(underlying)
			break
		case *tls.Conn:
			//log.Debugln("type tls")
			tlsConn = underlying
			c.netConn = underlying.NetConn()
			t = reflect.TypeOf(underlying).Elem()
			p = unsafe.Pointer(underlying)
			break
		case *tlsC.Conn:
			//log.Debugln("type *tlsC.Conn")
			tlsConn = underlying
			c.netConn = underlying.NetConn()
			t = reflect.TypeOf(underlying).Elem()
			p = unsafe.Pointer(underlying)
			break
		case *tlsC.UConn:
			//log.Debugln("type *tlsC.UConn")
			tlsConn = underlying
			c.netConn = underlying.NetConn()
			t = reflect.TypeOf(underlying.Conn).Elem()
			//log.Debugln("t:%v", t)
			p = unsafe.Pointer(underlying.Conn)
			break
		case *encryption.CommonConn:
			//log.Debugln("type *encryption.CommonConn")
			tlsConn = underlying
			c.netConn = underlying.Conn
			t = reflect.TypeOf(underlying).Elem()
			p = unsafe.Pointer(underlying)
			break
		}
		if u, ok := upstream.(N.ReaderWithUpstream); !ok || !u.ReaderReplaceable() { // must replaceable
			break
		}
		if u, ok := upstream.(N.WithUpstreamReader); ok {
			upstream = u.UpstreamReader()
			continue
		}
		if u, ok := upstream.(N.WithUpstream); ok {
			upstream = u.Upstream()
			continue
		}
	}
	if t == nil || p == nil {
		log.Warnln("vision: not a valid supported TLS connection: %s", reflect.TypeOf(tlsConn))
		return nil, fmt.Errorf(`failed to use vision, maybe "tls" is not enable and "encryption" is empty`)
	}

	if err := checkTLSVersion(tlsConn); err != nil {
		if errors.Is(err, ErrNotHandshakeComplete) {
			log.Warnln("vision: TLS connection not handshake complete: %s", reflect.TypeOf(tlsConn))
		} else {
			return nil, err
		}
	}

	if i, ok := t.FieldByName("input"); ok {
		c.input = (*bytes.Reader)(unsafe.Add(p, i.Offset))
	}
	if r, ok := t.FieldByName("rawInput"); ok {
		c.rawInput = (*bytes.Buffer)(unsafe.Add(p, r.Offset))
	}
	return c, nil
}

func checkTLSVersion(tlsConn net.Conn) error {
	switch underlying := tlsConn.(type) {
	case *gotls.Conn:
		state := underlying.ConnectionState()
		if !state.HandshakeComplete {
			return ErrNotHandshakeComplete
		}
		if state.Version != gotls.VersionTLS13 {
			return ErrNotTLS13
		}
	case *tls.Conn:
		state := underlying.ConnectionState()
		if !state.HandshakeComplete {
			return ErrNotHandshakeComplete
		}
		if state.Version != tls.VersionTLS13 {
			return ErrNotTLS13
		}
	case *tlsC.Conn:
		state := underlying.ConnectionState()
		if !state.HandshakeComplete {
			return ErrNotHandshakeComplete
		}
		if state.Version != tlsC.VersionTLS13 {
			return ErrNotTLS13
		}
	case *tlsC.UConn:
		state := underlying.ConnectionState()
		if !state.HandshakeComplete {
			return ErrNotHandshakeComplete
		}
		if state.Version != tlsC.VersionTLS13 {
			return ErrNotTLS13
		}
	}
	return nil
}
