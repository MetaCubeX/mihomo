package trojan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/Dreamacro/clash/common/pool"
	tlsC "github.com/Dreamacro/clash/component/tls"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
	"github.com/Dreamacro/clash/transport/vless"
	"github.com/Dreamacro/clash/transport/vmess"
	xtls "github.com/xtls/go"
)

const (
	// max packet length
	maxLength = 8192
)

var (
	defaultALPN          = []string{"h2", "http/1.1"}
	defaultWebsocketALPN = []string{"http/1.1"}

	crlf = []byte{'\r', '\n'}
)

type Command = byte

const (
	CommandTCP byte = 1
	CommandUDP byte = 3

	// for XTLS
	commandXRD byte = 0xf0 // XTLS direct mode
	commandXRO byte = 0xf1 // XTLS origin mode
)

type Option struct {
	Password          string
	ALPN              []string
	ServerName        string
	SkipCertVerify    bool
	Fingerprint       string
	Flow              string
	FlowShow          bool
	ClientFingerprint string
}

type WebsocketOption struct {
	Host    string
	Port    string
	Path    string
	Headers http.Header
}

type Trojan struct {
	option      *Option
	hexPassword []byte
}

func (t *Trojan) StreamConn(conn net.Conn) (net.Conn, error) {
	alpn := defaultALPN
	if len(t.option.ALPN) != 0 {
		alpn = t.option.ALPN
	}
	switch t.option.Flow {
	case vless.XRO, vless.XRD, vless.XRS:
		xtlsConfig := &xtls.Config{
			NextProtos:         alpn,
			MinVersion:         xtls.VersionTLS12,
			InsecureSkipVerify: t.option.SkipCertVerify,
			ServerName:         t.option.ServerName,
		}

		if len(t.option.Fingerprint) == 0 {
			xtlsConfig = tlsC.GetGlobalXTLSConfig(xtlsConfig)
		} else {
			var err error
			if xtlsConfig, err = tlsC.GetSpecifiedFingerprintXTLSConfig(xtlsConfig, t.option.Fingerprint); err != nil {
				return nil, err
			}
		}

		xtlsConn := xtls.Client(conn, xtlsConfig)

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		if err := xtlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return xtlsConn, nil
	default:
		tlsConfig := &tls.Config{
			NextProtos:         alpn,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: t.option.SkipCertVerify,
			ServerName:         t.option.ServerName,
		}

		if len(t.option.Fingerprint) == 0 {
			tlsConfig = tlsC.GetGlobalTLSConfig(tlsConfig)
		} else {
			var err error
			if tlsConfig, err = tlsC.GetSpecifiedFingerprintTLSConfig(tlsConfig, t.option.Fingerprint); err != nil {
				return nil, err
			}
		}

		if len(t.option.ClientFingerprint) != 0 {
			utlsConn, valid := vmess.GetUtlsConnWithClientFingerprint(conn, t.option.ClientFingerprint, tlsConfig)
			if valid {
				ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
				defer cancel()

				err := utlsConn.(*vmess.UConn).HandshakeContext(ctx)
				return utlsConn, err

			}
		}

		tlsConn := tls.Client(conn, tlsConfig)

		// fix tls handshake not timeout
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()

		err := tlsConn.HandshakeContext(ctx)
		return tlsConn, err
	}
}

func (t *Trojan) StreamWebsocketConn(conn net.Conn, wsOptions *WebsocketOption) (net.Conn, error) {
	alpn := defaultWebsocketALPN
	if len(t.option.ALPN) != 0 {
		alpn = t.option.ALPN
	}

	tlsConfig := &tls.Config{
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: t.option.SkipCertVerify,
		ServerName:         t.option.ServerName,
	}

	return vmess.StreamWebsocketConn(conn, &vmess.WebsocketConfig{
		Host:              wsOptions.Host,
		Port:              wsOptions.Port,
		Path:              wsOptions.Path,
		Headers:           wsOptions.Headers,
		TLS:               true,
		TLSConfig:         tlsConfig,
		ClientFingerprint: t.option.ClientFingerprint,
	})
}

func (t *Trojan) PresetXTLSConn(conn net.Conn) (net.Conn, error) {
	switch t.option.Flow {
	case vless.XRO, vless.XRD, vless.XRS:
		if xtlsConn, ok := conn.(*xtls.Conn); ok {
			xtlsConn.RPRX = true
			xtlsConn.SHOW = t.option.FlowShow
			xtlsConn.MARK = "XTLS"
			if t.option.Flow == vless.XRS {
				t.option.Flow = vless.XRD
			}

			if t.option.Flow == vless.XRD {
				xtlsConn.DirectMode = true
			}
		} else {
			return conn, fmt.Errorf("failed to use %s, maybe \"security\" is not \"xtls\"", t.option.Flow)
		}
	}

	return conn, nil
}

func (t *Trojan) WriteHeader(w io.Writer, command Command, socks5Addr []byte) error {
	if command == CommandTCP {
		if t.option.Flow == vless.XRD {
			command = commandXRD
		} else if t.option.Flow == vless.XRO {
			command = commandXRO
		}
	}

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	buf.Write(t.hexPassword)
	buf.Write(crlf)

	buf.WriteByte(command)
	buf.Write(socks5Addr)
	buf.Write(crlf)

	_, err := w.Write(buf.Bytes())
	return err
}

func (t *Trojan) PacketConn(conn net.Conn) net.PacketConn {
	return &PacketConn{
		Conn: conn,
	}
}

func writePacket(w io.Writer, socks5Addr, payload []byte) (int, error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	buf.Write(socks5Addr)
	binary.Write(buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(crlf)
	buf.Write(payload)

	return w.Write(buf.Bytes())
}

func WritePacket(w io.Writer, socks5Addr, payload []byte) (int, error) {
	if len(payload) <= maxLength {
		return writePacket(w, socks5Addr, payload)
	}

	offset := 0
	total := len(payload)
	for {
		cursor := offset + maxLength
		if cursor > total {
			cursor = total
		}

		n, err := writePacket(w, socks5Addr, payload[offset:cursor])
		if err != nil {
			return offset + n, err
		}

		offset = cursor
		if offset == total {
			break
		}
	}

	return total, nil
}

func ReadPacket(r io.Reader, payload []byte) (net.Addr, int, int, error) {
	addr, err := socks5.ReadAddr(r, payload)
	if err != nil {
		return nil, 0, 0, errors.New("read addr error")
	}
	uAddr := addr.UDPAddr()
	if uAddr == nil {
		return nil, 0, 0, errors.New("parse addr error")
	}

	if _, err = io.ReadFull(r, payload[:2]); err != nil {
		return nil, 0, 0, errors.New("read length error")
	}

	total := int(binary.BigEndian.Uint16(payload[:2]))
	if total > maxLength {
		return nil, 0, 0, errors.New("packet invalid")
	}

	// read crlf
	if _, err = io.ReadFull(r, payload[:2]); err != nil {
		return nil, 0, 0, errors.New("read crlf error")
	}

	length := len(payload)
	if total < length {
		length = total
	}

	if _, err = io.ReadFull(r, payload[:length]); err != nil {
		return nil, 0, 0, errors.New("read packet error")
	}

	return uAddr, length, total - length, nil
}

func New(option *Option) *Trojan {
	return &Trojan{option, hexSha224([]byte(option.Password))}
}

type PacketConn struct {
	net.Conn
	remain int
	rAddr  net.Addr
	mux    sync.Mutex
}

func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return WritePacket(pc, socks5.ParseAddr(addr.String()), b)
}

func (pc *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.mux.Lock()
	defer pc.mux.Unlock()
	if pc.remain != 0 {
		length := len(b)
		if pc.remain < length {
			length = pc.remain
		}

		n, err := pc.Conn.Read(b[:length])
		if err != nil {
			return 0, nil, err
		}

		pc.remain -= n
		addr := pc.rAddr
		if pc.remain == 0 {
			pc.rAddr = nil
		}

		return n, addr, nil
	}

	addr, n, remain, err := ReadPacket(pc.Conn, b)
	if err != nil {
		return 0, nil, err
	}

	if remain != 0 {
		pc.remain = remain
		pc.rAddr = addr
	}

	return n, addr, nil
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
