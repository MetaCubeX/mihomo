// Package muxcool 实现 Xray 的 Mux.cool 多路复用线协议(帧编解码 + 服务端会话)。
//
// 用途:让 mihomo 当反向代理的 Bridge —— 在一条 VLESS(Rvs 命令)隧道之上跑 Mux.cool
// 服务端,被动接收 Portal(Xray)开来的子流并落地到本地内网。
//
// 本文件只含"帧层"(codec):FrameMetadata 读写 + 数据分块 + port-then-address 地址编解码。
// 会话状态机(ServerWorker)在 server.go。
//
// 与 mihomo 自带的 sing-mux(yamux/smux/h2mux)完全不同、不可复用——那是别的多路复用协议。
// 字节布局对齐 Xray-core common/mux/frame.go(全 big-endian)。
package muxcool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// SessionStatus —— 子流状态(Xray common/mux/frame.go:19-24)。
type SessionStatus byte

const (
	StatusNew       SessionStatus = 0x01 // 新子流(带目标地址)
	StatusKeep      SessionStatus = 0x02 // 续传数据(响应流首帧也是 Keep)
	StatusEnd       SessionStatus = 0x03 // 关子流
	StatusKeepAlive SessionStatus = 0x04 // 纯心跳,收到丢弃;我方从不主动发
)

// Option —— 位掩码(frame.go:26-29)。
type Option byte

const (
	OptionData  Option = 0x01 // 该帧带数据段
	OptionError Option = 0x02 // 出错(用于 End 帧)
)

func (o Option) Has(f Option) bool { return o&f != 0 }

// TargetNetwork —— 目标网络字节(frame.go:31-36)。注意与 source/local 的 Network-1 编码不同。
type TargetNetwork byte

const (
	NetworkTCP TargetNetwork = 0x01
	NetworkUDP TargetNetwork = 0x02
)

// 地址类型字节 —— Xray 这套(common/protocol/payload.go:13-15)。
// ⚠ 与 mihomo 的 constant.AddrType(Domain=3/IPv6=4)不同,codec 内部一律用这套。
const (
	atypIPv4   byte = 0x01
	atypDomain byte = 0x02
	atypIPv6   byte = 0x03
)

// metaLen 上限(frame.go:119)。
const maxMetaLen = 512

// StreamChunkSize —— TCP(Stream)每帧数据上限(writer.go:107 SplitSize 8*1024)。
const StreamChunkSize = 8 * 1024

var (
	ErrMetaTooLong  = errors.New("muxcool: metaLen exceeds 512")
	ErrMetaTooShort = errors.New("muxcool: metaLen < 4")
	ErrDataTooLong  = errors.New("muxcool: data chunk exceeds 8192")
)

// Address —— 目标地址(域名或 IP)。Host 为域名时 IsDomain=true。
type Address struct {
	IsDomain bool
	Domain   string
	IP       net.IP // 4 或 16 字节
}

func (a Address) String() string {
	if a.IsDomain {
		return a.Domain
	}
	return a.IP.String()
}

// AddrFromString —— 从字符串构造 Address(是 IP 走 IP,否则当域名)。
func AddrFromString(s string) Address {
	if ip := net.ParseIP(s); ip != nil {
		return Address{IP: ip}
	}
	return Address{IsDomain: true, Domain: s}
}

// FrameMetadata —— 一个 Mux.cool 帧的元数据体(不含 metaLen 前缀,不含数据段)。
type FrameMetadata struct {
	SessionID uint16
	Status    SessionStatus
	Option    Option

	// 目标地址块 —— 仅 New,或 (Keep 且 UDP) 时有意义。
	Network TargetNetwork
	Address Address
	Port    uint16
}

// -------------------------------------------------------------------------
// 地址编解码(PortThenAddress:端口在前、类型字节、地址)
// -------------------------------------------------------------------------

// writeAddrPort 把 [2B port][1B atyp][addr] 追加到 b。
func writeAddrPort(b []byte, port uint16, addr Address) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, port)
	switch {
	case addr.IsDomain:
		if len(addr.Domain) > 255 {
			return nil, fmt.Errorf("muxcool: domain too long: %d", len(addr.Domain))
		}
		b = append(b, atypDomain, byte(len(addr.Domain)))
		b = append(b, addr.Domain...)
	case addr.IP.To4() != nil:
		b = append(b, atypIPv4)
		b = append(b, addr.IP.To4()...)
	default:
		b = append(b, atypIPv6)
		b = append(b, addr.IP.To16()...)
	}
	return b, nil
}

// readAddrPort 从 buf(off 起)读 [2B port][1B atyp][addr],返回 addr/port 及新偏移。
func readAddrPort(buf []byte, off int) (Address, uint16, int, error) {
	if off+3 > len(buf) {
		return Address{}, 0, off, io.ErrUnexpectedEOF
	}
	port := binary.BigEndian.Uint16(buf[off:])
	off += 2
	atyp := buf[off]
	off++
	switch atyp {
	case atypIPv4:
		if off+4 > len(buf) {
			return Address{}, 0, off, io.ErrUnexpectedEOF
		}
		ip := make(net.IP, 4)
		copy(ip, buf[off:off+4])
		return Address{IP: ip}, port, off + 4, nil
	case atypIPv6:
		if off+16 > len(buf) {
			return Address{}, 0, off, io.ErrUnexpectedEOF
		}
		ip := make(net.IP, 16)
		copy(ip, buf[off:off+16])
		return Address{IP: ip}, port, off + 16, nil
	case atypDomain:
		if off+1 > len(buf) {
			return Address{}, 0, off, io.ErrUnexpectedEOF
		}
		dlen := int(buf[off])
		off++
		if off+dlen > len(buf) {
			return Address{}, 0, off, io.ErrUnexpectedEOF
		}
		return Address{IsDomain: true, Domain: string(buf[off : off+dlen])}, port, off + dlen, nil
	default:
		return Address{}, 0, off, fmt.Errorf("muxcool: bad address type 0x%02x", atyp)
	}
}

// -------------------------------------------------------------------------
// 元数据体编码
// -------------------------------------------------------------------------

// marshalMeta 生成"元数据体"字节(不含 metaLen 前缀)。
// 只写 target 地址块;不写 source/local/GlobalID(Bridge 作为服务端只发 Keep/End,
// New 仅测试/客户端场景用,且我们按 IsReverseMux=false 语义不带这些尾部)。
func (m *FrameMetadata) marshalMeta() ([]byte, error) {
	b := make([]byte, 0, 16)
	b = binary.BigEndian.AppendUint16(b, m.SessionID)
	b = append(b, byte(m.Status), byte(m.Option))
	// New,或 (Keep 且 UDP) 时写目标地址块。
	if m.Status == StatusNew || (m.Status == StatusKeep && m.Network == NetworkUDP) {
		b = append(b, byte(m.Network))
		var err error
		b, err = writeAddrPort(b, m.Port, m.Address)
		if err != nil {
			return nil, err
		}
	}
	if len(b) > maxMetaLen {
		return nil, ErrMetaTooLong
	}
	return b, nil
}

// unmarshalMeta 解析"元数据体"字节。读到 target 地址即停,剩余字节(source/local/GlobalID)
// 一律忽略 —— 这样形态 A(无尾部)/形态 B(有 source/local)用同一份代码。
func unmarshalMeta(buf []byte) (*FrameMetadata, error) {
	if len(buf) < 4 {
		return nil, ErrMetaTooShort
	}
	m := &FrameMetadata{
		SessionID: binary.BigEndian.Uint16(buf[0:]),
		Status:    SessionStatus(buf[2]),
		Option:    Option(buf[3]),
	}
	off := 4
	// 是否带目标地址:New;或 Keep 且下一字节==UDP(frame.go:144)。
	hasAddr := m.Status == StatusNew ||
		(m.Status == StatusKeep && off < len(buf) && buf[off] == byte(NetworkUDP))
	if hasAddr {
		if off >= len(buf) {
			return nil, io.ErrUnexpectedEOF
		}
		m.Network = TargetNetwork(buf[off])
		off++
		addr, port, _, err := readAddrPort(buf, off)
		if err != nil {
			return nil, err
		}
		m.Address, m.Port = addr, port
		// 剩余 source/local/GlobalID 忽略。
	}
	return m, nil
}

// -------------------------------------------------------------------------
// 帧读写(线上:[2B metaLen][meta][2B dataLen][data],后半仅 Option&Data 时存在)
// -------------------------------------------------------------------------

// WriteFrame 写一个完整帧。data 为该帧负载(可 nil);data 非空时自动置 OptionData。
// data 必须 ≤ StreamChunkSize(上层用 WriteData 分块)。
func WriteFrame(w io.Writer, m *FrameMetadata, data []byte) error {
	if len(data) > StreamChunkSize {
		return ErrDataTooLong
	}
	if len(data) > 0 {
		m.Option |= OptionData
	}
	meta, err := m.marshalMeta()
	if err != nil {
		return err
	}
	// [metaLen][meta]
	hdr := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(meta)+2), uint16(len(meta)))
	hdr = append(hdr, meta...)
	// [dataLen][data](仅 Option&Data)
	if m.Option.Has(OptionData) {
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(data)))
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if m.Option.Has(OptionData) && len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// WriteData 把一段 payload 按 8KB 切成多个 Keep 帧写出(用于 Bridge 回程响应)。
// 空 payload 不发帧(如需 keepalive 另行处理)。
func WriteData(w io.Writer, sessionID uint16, data []byte) error {
	for len(data) > 0 {
		n := len(data)
		if n > StreamChunkSize {
			n = StreamChunkSize
		}
		m := &FrameMetadata{SessionID: sessionID, Status: StatusKeep, Option: OptionData}
		if err := WriteFrame(w, m, data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// WriteEnd 写一个 End 帧关闭子流;hasError 置 OptionError。
func WriteEnd(w io.Writer, sessionID uint16, hasError bool) error {
	m := &FrameMetadata{SessionID: sessionID, Status: StatusEnd}
	if hasError {
		m.Option |= OptionError
	}
	return WriteFrame(w, m, nil)
}

// ReadFrame 从 r 读一个完整帧,返回元数据与数据段(无数据段则 data 为 nil)。
// 会跳过 metaLen 内的 source/local/GlobalID 尾部。
func ReadFrame(r io.Reader) (*FrameMetadata, []byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, nil, err
	}
	metaLen := int(binary.BigEndian.Uint16(lb[:]))
	if metaLen > maxMetaLen {
		return nil, nil, ErrMetaTooLong
	}
	if metaLen < 4 {
		return nil, nil, ErrMetaTooShort
	}
	metaBuf := make([]byte, metaLen)
	if _, err := io.ReadFull(r, metaBuf); err != nil {
		return nil, nil, err
	}
	m, err := unmarshalMeta(metaBuf)
	if err != nil {
		return nil, nil, err
	}
	var data []byte
	if m.Option.Has(OptionData) {
		if _, err := io.ReadFull(r, lb[:]); err != nil {
			return nil, nil, err
		}
		dataLen := int(binary.BigEndian.Uint16(lb[:]))
		if dataLen > StreamChunkSize {
			return nil, nil, ErrDataTooLong
		}
		if dataLen > 0 {
			data = make([]byte, dataLen)
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, nil, err
			}
		}
	}
	return m, data, nil
}
