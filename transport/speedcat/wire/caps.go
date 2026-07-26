package wire

import "encoding/binary"

// Caps —— 能力位(u16)。
//
// 位旗(bit 0-4)按位与取交集;FEC_RATIO 枚举(bit 5-7)需双方声明相同非零值才生效(等值匹配,非位与);
// NO_INNER_AEAD(bit 8)快路自动置位(exporter 双方都在时);bit 9-15 reserved 须 0。
type Caps uint16

// 能力位旗。
const (
	CapHasDatagram Caps = 1 << 0 // HAS_DATAGRAM:传输层有原生 UDP datagram(仅 QUIC 置位);隐含承诺实现 分片重组
	CapMUX         Caps = 1 << 1 // MUX:支持多路复用(多流/连接)
	CapPadding     Caps = 1 << 2 // PADDING:支持填充帧(抗流量分析)
	CapBrutalCC    Caps = 1 << 3 // BRUTAL_CC:支持 Brutal 拥塞控制(实际带宽走握手 max_bandwidth:u32)
	CapUDPTunnelOK Caps = 1 << 4 // UDP_TUNNEL_OK:接受流内隧道化 UDP(TCP binding 必置)
	CapNoInnerAEAD Caps = 1 << 8 // NO_INNER_AEAD:帧无 tag、payload 明文(快路 exporter 双方在时自动置位)
)

// FEC_RATIO 占 bit 5-7(3 位枚举):0=off / 1=4:1 / 2=10:3 / 3=10:10。
const (
	fecRatioShift uint = 5
	fecRatioMask  Caps = 0b0000_0000_1110_0000 // bit 5-7
	reservedMask  Caps = 0b1111_1110_0000_0000 // bit 9-15(reserved,须 0)
)

// FECRatio 返回 FEC 比率枚举(bit 5-7)。
func (c Caps) FECRatio() uint8 { return uint8((c & fecRatioMask) >> fecRatioShift) }

// SetFECRatio 设置 FEC 比率枚举(r 取低 3 位)。
func (c *Caps) SetFECRatio(r uint8) {
	*c = (*c &^ fecRatioMask) | (Caps(r&0b111) << fecRatioShift)
}

// Has 报告位旗是否置位。
func (c Caps) Has(flag Caps) bool { return c&flag == flag }

// NoInnerAEAD 报告 NO_INNER_AEAD(bit 8)是否置位(对照 Rust no_inner_aead,caps.rs:39-41)。
// 快路 exporter 双方在时自动置位 → 帧无 tag、payload 明文。
func (c Caps) NoInnerAEAD() bool { return c&CapNoInnerAEAD != 0 }

// SetNoInnerAEAD 置/清 NO_INNER_AEAD(bit 8,对照 Rust set_no_inner_aead,caps.rs:60-63)。
// 指针 receiver(与 SetFECRatio 同款,原地改)。握手期 force 置/清(架构不变量 :
// 快路 force 置位 / 伪装路 force 清位,caps 位 == crypto flag 单一真相源)。
func (c *Caps) SetNoInnerAEAD(v bool) {
	if v {
		*c |= CapNoInnerAEAD
	} else {
		*c &^= CapNoInnerAEAD
	}
}

// Padding 报告 PADDING(bit 2)是否置位(对照 Rust padding,caps.rs:45-47)。21 单栈伪装路默认 offer;
// encode 塑形落 pumpEncodeFast(快路 + caps PADDING),decode 两侧无条件消费 Padding(不门控 caps)。
func (c Caps) Padding() bool { return c&CapPadding != 0 }

// SetPadding 置/清 PADDING(bit 2,对照 Rust set_padding,caps.rs:66-69)。指针 receiver(与 SetNoInnerAEAD
// 同款,原地改)。client 侧按 transport kind gate(TCP/raw-tcp offer / QUIC 不 offer,见 client.NewClient)。
func (c *Caps) SetPadding(v bool) {
	if v {
		*c |= CapPadding
	} else {
		*c &^= CapPadding
	}
}

// Valid 报告 reserved 位(bit 9-15)是否全 0(「reserved 须置 0」)。
func (c Caps) Valid() bool { return c&reservedMask == 0 }

// Bytes 序列化 caps 为 2B 大端(对照 Rust to_bytes,caps.rs:74-76)。写 ClientHello caps_c /
// ServerHello caps_s / FastHello caps_c(全大端)。返回数组(栈分配,零逃逸 —— 热路径友好)。
func (c Caps) Bytes() [2]byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(c))
	return b
}

// FromBytes 从 2B 大端反序列化 caps(对照 Rust from_bytes,caps.rs:77-79)。client 读 ServerHello
// caps_s 时用。
func FromBytes(b [2]byte) Caps { return Caps(binary.BigEndian.Uint16(b[:])) }

// Negotiate 取握手能力交集(有效交集规则)。
//
// 位旗按位与;FEC_RATIO 需双方声明相同非零值才生效,否则 off;reserved 位(bit 9-15)强制清零(防对端乱置)。
//
// **FEC 残留清除(review follow-up):** 额外清 FEC 位(bit 5-7),对齐 Rust allowlist
// `c & s & 0x011F`(caps.rs:93,mask 只含 bit 0-4、8,**不含** FEC 位)—— 否则双方声明不同非零
// FEC 时,(client&server) 的 FEC 位 AND 残留会留在 out(如 client FEC=1、server=3 → 残留 bit5),
// 与 Rust(FEC 位先恒清零、再单独写协商值)分叉。该残留会经 DisguiseHSInput 进 MAC →
// handshake_secret → 伪装路会话密钥分叉。快路 auth_tag 绑 raw caps、不经 negotiate,不受影响。
func Negotiate(client, server Caps) Caps {
	out := (client & server) &^ (reservedMask | fecRatioMask) // 位旗位与 + 清 reserved + 清 FEC 残留
	fec := client.FECRatio()
	if fec != 0 && fec == server.FECRatio() {
		out.SetFECRatio(fec)
	}
	return out
}
