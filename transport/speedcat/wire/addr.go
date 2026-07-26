package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// AddrType —— 地址类型。atype 取值同 VLESS/v2ray(domain=0x02),字节序 addr-then-port(同 SOCKS5/Trojan)。
type AddrType byte

const (
	AddrTypeIPv4   AddrType = 0x01 // IPv4(后接 4 字节)
	AddrTypeDomain AddrType = 0x02 // 域名(后接 1 字节长度 + N 字节)
	AddrTypeIPv6   AddrType = 0x03 // IPv6(后接 16 字节)
	// 0xff = ADDR_TYPE_NONE 仅用于 UDP datagram 非首片占位(TUIC trick),不在通用 Addr;datagram 包处理。
)

// Addr 编解码错误。
var (
	ErrAddrTruncated     = errors.New("speedcat/wire: addr truncated")
	ErrAddrTypeUnknown   = errors.New("speedcat/wire: unknown addr type")
	ErrAddrDomainTooLong = errors.New("speedcat/wire: domain label too long (>255)")
)

// Addr 表示一个 host:port 目标。Domain 不在本地解析(避免 DNS 泄漏,09 §3)。
type Addr struct {
	Type   AddrType
	IPv4   [4]byte  // Type == AddrTypeIPv4 有效
	IPv6   [16]byte // Type == AddrTypeIPv6 有效
	Domain string   // Type == AddrTypeDomain 有效(长度 ≤ 255,单字节长度前缀)
	Port   uint16   // 大端序列化
}

// MarshalBinary 编码 Addr:atype(1) + addr(变长) + port(2,BE)。
func (a Addr) MarshalBinary() ([]byte, error) {
	switch a.Type {
	case AddrTypeIPv4:
		b := make([]byte, 1+4+2)
		b[0] = byte(a.Type)
		copy(b[1:5], a.IPv4[:])
		binary.BigEndian.PutUint16(b[5:7], a.Port)
		return b, nil
	case AddrTypeIPv6:
		b := make([]byte, 1+16+2)
		b[0] = byte(a.Type)
		copy(b[1:17], a.IPv6[:])
		binary.BigEndian.PutUint16(b[17:19], a.Port)
		return b, nil
	case AddrTypeDomain:
		if len(a.Domain) > 255 {
			return nil, ErrAddrDomainTooLong
		}
		b := make([]byte, 1+1+len(a.Domain)+2)
		b[0] = byte(a.Type)
		b[1] = byte(len(a.Domain))
		copy(b[2:2+len(a.Domain)], a.Domain)
		binary.BigEndian.PutUint16(b[2+len(a.Domain):4+len(a.Domain)], a.Port)
		return b, nil
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrAddrTypeUnknown, a.Type)
	}
}

// WriteTo 把 Addr 写入 w(流式,与 MarshalBinary 同字节)。
func (a Addr) WriteTo(w io.Writer) (int64, error) {
	b, err := a.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

// DecodeAddr 从 b 开头解码 Addr,返回 Addr 与消耗的字节数。
func DecodeAddr(b []byte) (Addr, int, error) {
	if len(b) < 1 {
		return Addr{}, 0, ErrAddrTruncated
	}
	switch at := AddrType(b[0]); at {
	case AddrTypeIPv4:
		if len(b) < 1+4+2 {
			return Addr{}, 0, ErrAddrTruncated
		}
		var a Addr
		a.Type = at
		copy(a.IPv4[:], b[1:5])
		a.Port = binary.BigEndian.Uint16(b[5:7])
		return a, 7, nil
	case AddrTypeIPv6:
		if len(b) < 1+16+2 {
			return Addr{}, 0, ErrAddrTruncated
		}
		var a Addr
		a.Type = at
		copy(a.IPv6[:], b[1:17])
		a.Port = binary.BigEndian.Uint16(b[17:19])
		return a, 19, nil
	case AddrTypeDomain:
		if len(b) < 1+1 {
			return Addr{}, 0, ErrAddrTruncated
		}
		l := int(b[1])
		if len(b) < 1+1+l+2 {
			return Addr{}, 0, ErrAddrTruncated
		}
		var a Addr
		a.Type = at
		a.Domain = string(b[2 : 2+l])
		a.Port = binary.BigEndian.Uint16(b[2+l : 4+l])
		return a, 4 + l, nil
	default:
		return Addr{}, 0, fmt.Errorf("%w: 0x%02x", ErrAddrTypeUnknown, b[0])
	}
}

// ReadAddr 从 r 流式读 Addr(先 atype 再按类型读定长/变长体)。
func ReadAddr(r io.Reader) (Addr, error) {
	var head [1]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Addr{}, err
	}
	at := AddrType(head[0])
	var a Addr
	a.Type = at
	switch at {
	case AddrTypeIPv4:
		var buf [4 + 2]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Addr{}, err
		}
		copy(a.IPv4[:], buf[:4])
		a.Port = binary.BigEndian.Uint16(buf[4:6])
	case AddrTypeIPv6:
		var buf [16 + 2]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Addr{}, err
		}
		copy(a.IPv6[:], buf[:16])
		a.Port = binary.BigEndian.Uint16(buf[16:18])
	case AddrTypeDomain:
		var lp [1]byte
		if _, err := io.ReadFull(r, lp[:]); err != nil {
			return Addr{}, err
		}
		l := int(lp[0])
		dom := make([]byte, l+2)
		if _, err := io.ReadFull(r, dom); err != nil {
			return Addr{}, err
		}
		a.Domain = string(dom[:l])
		a.Port = binary.BigEndian.Uint16(dom[l : l+2])
	default:
		return Addr{}, fmt.Errorf("%w: 0x%02x", ErrAddrTypeUnknown, at)
	}
	return a, nil
}

// String 人类可读(host:port);IPv6 用 [..]:port。
func (a Addr) String() string {
	switch a.Type {
	case AddrTypeIPv4:
		return fmt.Sprintf("%d.%d.%d.%d:%d", a.IPv4[0], a.IPv4[1], a.IPv4[2], a.IPv4[3], a.Port)
	case AddrTypeIPv6:
		return fmt.Sprintf("[%s]:%d", net.IP(a.IPv6[:]).String(), a.Port)
	case AddrTypeDomain:
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)
	default:
		return fmt.Sprintf("<bad addr type 0x%02x>", a.Type)
	}
}
