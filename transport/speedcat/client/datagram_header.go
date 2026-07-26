// datagram_header.go —— datagram header + 分片/重组(镜像 Rust udp.rs:115-461;**仅 datagram 路**)。
//
// **为何只在 datagram 路用:** QUIC datagram 有 max size 上限(~1.2K,含 QUIC framing overhead),大 UDP 报文须按
// 切片逐 datagram 发,接收方 [ReassemblyBuffer] 重组。流内隧道(TCP fallback)走 stream 帧层(u16 len,
// 单帧可达 64K),**不分片**。两分片域独立:SOCKS5 FRAG 恒 0(我们在 SOCKS5 层不分片)。
//
// # 线格式(DatagramHeader + frag_payload,整体经 DatagramCipher.Seal 加密)
//
//	[ASSOC_ID:u16][PKT_ID:u16][FRAG_TOTAL:u8][FRAG_ID:u8][SIZE:u16][ADDR|0xff][frag_payload]
//
//	- 首片(frag_id==0)带完整 ADDR(目标/源);非首片单字节 0xff 占位(TUIC trick,省空间)。
//	- SIZE = 整包重组后字节数(接收方完成时校验)。
//	- PKT_ID 客户端单调/随机指派;(ASSOC_ID,PKT_ID) 唯一定位一个待重组包。
//
// # ReassemblyBuffer 四校验(fail-loud → Err;relay 循环据此丢该包不杀关联)
//
//  1. frag_id < frag_total(否则畸形)。
//  2. 同包跨片 frag_total/size 一致(否则 pkt_id 复用冲突)。
//  3. addr 一致性:首片须 Some、非首片须 None。
//  4. 集齐时拼接长度 == size(否则截断/错位)。
//
// 幂等:重复 frag_id / 重复首片覆盖(UDP 可重传 → 不报错,不累加)。GC:清超期未集齐包(生命周期)。
//
// **热路径:** Fragment/Insert 在每 UDP 报文同步段(MVP 每 frag 一次 alloc);零日志。零拷贝留收尾。
// **panic-free**(被 mihomo import 的库:校验错返 error)。

package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// AddrTypeNone 非首片 ADDR 占位标记(TUIC trick:复用 0xff,与 Addr atype 0x01/0x02/0x03 不冲突;
// 对照 Rust udp.rs:33 ADDR_TYPE_NONE)。
const AddrTypeNone byte = 0xff

// MVPMaxDatagramSize 单 datagram 上限 fallback(对照 Rust MVP_MAX_DATAGRAM_SIZE=1200)。
// quinn max_datagram_size() 已含 QUIC framing overhead(gotcha #2);quic-go 无直接 max-size 方法(仅 SendDatagram
// 错误暴露),用此常量作 fallback:调用方再扣 AEAD nonce/tag 得每片 plaintext 上限。
const MVPMaxDatagramSize = 1200

// GC 间隔 / 分片最长存活(对照 Rust GC_INTERVAL=10s / GC_LIFETIME=30s)。
const (
	GcInterval = 10 * time.Second
	GcLifetime = 30 * time.Second
)

// datagram 分片/重组错误(fail-loud;对照 Rust udp.rs 各 Error::Wire 分支)。
var (
	ErrDgHeaderTruncated   = errors.New("client/dg: header 截断(< 8B)")
	ErrDgMissingMarker     = errors.New("client/dg: 非首片缺 ADDR_TYPE_NONE 标记")
	ErrDgBadMarker         = errors.New("client/dg: 非首片须 0xff ADDR_TYPE_NONE")
	ErrDgMissingAddr       = errors.New("client/dg: 首片缺 addr")
	ErrDgNonFirstHasAddr   = errors.New("client/dg: 非首片带 addr(畸形)")
	ErrFragIdGEFragTotal   = errors.New("client/dg: frag_id >= frag_total")
	ErrFragBudgetTooSmall  = errors.New("client/dg: max_plain 容不下 header")
	ErrFragPayloadTooLarge = errors.New("client/dg: payload > u16::MAX")
	ErrFragTooMany         = errors.New("client/dg: 分片数 > 255 / frag_id > 255")
	ErrReasmConflict       = errors.New("client/dg: pkt_id 冲突(frag_total/size 不一致)")
	ErrReasmLenMismatch    = errors.New("client/dg: 重组长度 ≠ size")
	ErrReasmMissingAddr    = errors.New("client/dg: 集齐但缺 addr(首片丢失,不应发生)")
)

// DatagramHeaderFixedLen 固定前缀字节数(assoc_id + pkt_id + frag_total + frag_id + size = 2+2+1+1+2=8;
// 对照 Rust DatagramHeader::FIXED_LEN)。
const DatagramHeaderFixedLen = 8

// DatagramHeader 单 datagram 的 header(仅 datagram 路;明文经 DatagramCipher.Seal 加密)。
// 对照 Rust udp.rs:123 DatagramHeader。
type DatagramHeader struct {
	AssocID   uint16
	PktID     uint16
	FragTotal uint8
	FragID    uint8
	Size      uint16
	// Addr 首片 Some(完整目标/源);非首片 nil(线格式占位 0xff)。
	Addr *wire.Addr
}

// DatagramFrag 一片分片(header + payload),供 datagram 路逐片 EncodeWithPayload + Seal + SendDatagram。
type DatagramFrag struct {
	H       DatagramHeader
	Payload []byte
}

// EncodeWithPayload 编码整个 datagram 明文 = header + frag_payload(供 DatagramCipher.Seal)。
// 对照 Rust DatagramHeader::encode_with_payload。
func (h DatagramHeader) EncodeWithPayload(frag []byte) ([]byte, error) {
	v := make([]byte, 0, DatagramHeaderFixedLen+32+len(frag))
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], h.AssocID)
	v = append(v, b2[:]...)
	binary.BigEndian.PutUint16(b2[:], h.PktID)
	v = append(v, b2[:]...)
	v = append(v, h.FragTotal, h.FragID)
	binary.BigEndian.PutUint16(b2[:], h.Size)
	v = append(v, b2[:]...)
	if h.Addr != nil {
		ab, err := h.Addr.MarshalBinary()
		if err != nil {
			return nil, err
		}
		v = append(v, ab...)
	} else {
		v = append(v, AddrTypeNone)
	}
	v = append(v, frag...)
	return v, nil
}

// DecodeDatagramHeader 解码 → (header, frag_payload 切片)。frag_id==0 解 Addr;非首片期望单字节 0xff。
// 对照 Rust DatagramHeader::decode。
func DecodeDatagramHeader(buf []byte) (DatagramHeader, []byte, error) {
	if len(buf) < DatagramHeaderFixedLen {
		return DatagramHeader{}, nil, fmt.Errorf("%w: %d < %d", ErrDgHeaderTruncated, len(buf), DatagramHeaderFixedLen)
	}
	h := DatagramHeader{
		AssocID:   binary.BigEndian.Uint16(buf[0:2]),
		PktID:     binary.BigEndian.Uint16(buf[2:4]),
		FragTotal: buf[4],
		FragID:    buf[5],
		Size:      binary.BigEndian.Uint16(buf[6:8]),
	}
	after := buf[DatagramHeaderFixedLen:]
	if h.FragID == 0 {
		// 首片:带完整 Addr(自定界 via atype)。
		addr, n, err := wire.DecodeAddr(after)
		if err != nil {
			return DatagramHeader{}, nil, err
		}
		ac := addr
		h.Addr = &ac
		return h, after[n:], nil
	}
	// 非首片:期望单字节 0xff 占位。
	if len(after) < 1 {
		return DatagramHeader{}, nil, ErrDgMissingMarker
	}
	if after[0] != AddrTypeNone {
		// fail-loud:非首片必须 0xff;收到真实 atype = 发送端 bug / 篡改。
		return DatagramHeader{}, nil, fmt.Errorf("%w: 得 0x%02x", ErrDgBadMarker, after[0])
	}
	return h, after[1:], nil
}

// Fragment 把一个 UDP 报文按 切成若干 DatagramFrag(供 datagram 路逐片 seal+send)。
// maxPlain = 单 datagram 明文上限(**含** header,已由调用方扣 AEAD nonce/tag)。
// 首片 header 较大(带 Addr),后续片 header 仅 FIXED_LEN+1(0xff)→ 两档预算分别计算。
// 对照 Rust udp.rs:201 fragment。
func Fragment(assocID, pktID uint16, addr *wire.Addr, payload []byte, maxPlain int) ([]DatagramFrag, error) {
	addrBytes, err := addr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	firstHdrLen := DatagramHeaderFixedLen + len(addrBytes)
	restHdrLen := DatagramHeaderFixedLen + 1 // 0xff 占位

	if maxPlain <= firstHdrLen {
		// 首片 header 都装不下(+1B payload)→ 畸形 max_plain,fail-loud(对照 Rust first_budget==0 分支)。
		return nil, fmt.Errorf("%w: max_plain %d <= first hdr %d", ErrFragBudgetTooSmall, maxPlain, firstHdrLen)
	}
	firstBudget := maxPlain - firstHdrLen
	restBudget := maxPlain - restHdrLen

	total := len(payload)
	if total > 0xFFFF {
		return nil, fmt.Errorf("%w: %d", ErrFragPayloadTooLarge, total)
	}

	var out []DatagramFrag
	pos := 0
	fragID := 0
	for pos < total {
		budget := firstBudget
		if fragID != 0 {
			budget = restBudget
		}
		if budget == 0 {
			// 后续片 header 都装不下 → 永远切不完 → 畸形 max_plain,fail-loud。
			return nil, fmt.Errorf("%w: 后续分片 header", ErrFragBudgetTooSmall)
		}
		end := pos + budget
		if end > total {
			end = total
		}
		chunk := append([]byte(nil), payload[pos:end]...)
		h := DatagramHeader{
			AssocID:   assocID,
			PktID:     pktID,
			FragTotal: 0, // 占位,末尾统一回填
			FragID:    byte(fragID),
			Size:      uint16(total),
		}
		if fragID == 0 {
			ac := *addr
			h.Addr = &ac
		}
		out = append(out, DatagramFrag{H: h, Payload: chunk})
		pos = end
		fragID++
		if fragID > 255 {
			return nil, fmt.Errorf("%w: frag_id > 255", ErrFragTooMany)
		}
	}

	if len(out) == 0 {
		// payload 空 → 单个空分片(合法:UDP 可发空包,如 keepalive)。
		ac := *addr
		return []DatagramFrag{{H: DatagramHeader{
			AssocID: assocID, PktID: pktID, FragTotal: 1, FragID: 0, Size: 0, Addr: &ac,
		}, Payload: nil}}, nil
	}

	if len(out) > 255 {
		return nil, fmt.Errorf("%w: 分片数 %d", ErrFragTooMany, len(out))
	}
	fragTotal := byte(len(out))
	for i := range out {
		out[i].H.FragTotal = fragTotal
	}
	return out, nil
}

// dgKey ReassemblyBuffer 按 (assoc_id, pkt_id) 索引(对照 Rust HashMap<(u16,u16), _>)。
type dgKey struct {
	assoc, pkt uint16
}

// packetBuffer 单个待重组包的缓冲(对照 Rust udp.rs:295 PacketBuffer)。
type packetBuffer struct {
	frags     [][]byte // 按 frag_id 索引;nil = 该片未到(乱序/丢包)
	addr      *wire.Addr
	size      uint16
	fragTotal uint8
	created   time.Time
}

// ReassemblyBuffer 重组缓冲:按 (assoc_id, pkt_id) 收集分片,集齐即还原 (addr, payload)。
// 对照 Rust udp.rs:333 ReassemblyBuffer。
type ReassemblyBuffer struct {
	m map[dgKey]packetBuffer
}

// NewReassemblyBuffer 构造空重组缓冲。
func NewReassemblyBuffer() *ReassemblyBuffer {
	return &ReassemblyBuffer{m: make(map[dgKey]packetBuffer)}
}

// Insert 投入一分片。集齐 → (addr, payload, true);未集齐 → (nil, nil, false);校验失败 → Err。
// 对照 Rust ReassemblyBuffer::insert。
func (rb *ReassemblyBuffer) Insert(h DatagramHeader, frag []byte, now time.Time) (addr *wire.Addr, payload []byte, complete bool, err error) {
	// Rule 1:frag_id < frag_total(frag_total==0 也拒)。
	if h.FragTotal == 0 || h.FragID >= h.FragTotal {
		return nil, nil, false, fmt.Errorf("%w: frag_id %d >= frag_total %d", ErrFragIdGEFragTotal, h.FragID, h.FragTotal)
	}
	// Rule 3:addr 一致性(查 buffer 前验,仅依赖本片 header)。
	if h.FragID == 0 {
		if h.Addr == nil {
			return nil, nil, false, ErrDgMissingAddr
		}
	} else if h.Addr != nil {
		return nil, nil, false, ErrDgNonFirstHasAddr
	}

	key := dgKey{h.AssocID, h.PktID}
	if pb, ok := rb.m[key]; ok {
		// Rule 2:跨片 frag_total/size 一致。
		if pb.fragTotal != h.FragTotal || pb.size != h.Size {
			return nil, nil, false, fmt.Errorf("%w: pkt %d 存 %d/%d 来 %d/%d",
				ErrReasmConflict, h.PktID, pb.fragTotal, pb.size, h.FragTotal, h.Size)
		}
		if h.FragID == 0 {
			pb.addr = h.Addr // 幂等:重复首片覆盖
		}
		pb.frags[h.FragID] = append([]byte(nil), frag...) // 幂等:重复 frag 覆盖(拷贝防外部改)
		rb.m[key] = pb
	} else {
		frags := make([][]byte, h.FragTotal)
		frags[h.FragID] = append([]byte(nil), frag...)
		var a *wire.Addr
		if h.FragID == 0 {
			a = h.Addr
		}
		rb.m[key] = packetBuffer{frags: frags, addr: a, size: h.Size, fragTotal: h.FragTotal, created: now}
	}
	return rb.tryComplete(key)
}

// tryComplete 集齐则还原并移除 buffer;否则 (nil,nil,false)。Rule 4(拼接长度 == size)在此验。
func (rb *ReassemblyBuffer) tryComplete(key dgKey) (*wire.Addr, []byte, bool, error) {
	pb, ok := rb.m[key]
	if !ok {
		return nil, nil, false, nil
	}
	for _, f := range pb.frags {
		if f == nil {
			return nil, nil, false, nil // 未集齐
		}
	}
	delete(rb.m, key)

	// Rule 4:拼接长度须 == size。
	total := 0
	for _, f := range pb.frags {
		total += len(f)
	}
	if total != int(pb.size) {
		return nil, nil, false, fmt.Errorf("%w: %d != %d", ErrReasmLenMismatch, total, pb.size)
	}
	out := make([]byte, 0, total)
	for _, f := range pb.frags {
		out = append(out, f...)
	}
	if pb.addr == nil {
		return nil, nil, false, ErrReasmMissingAddr
	}
	return pb.addr, out, true, nil
}

// GC 清超期未集齐包(now - created >= lifetime)。relay 循环周期调(GcInterval)。
// 对照 Rust ReassemblyBuffer::gc(retain `now-created < lifetime`,此处取反删)。
func (rb *ReassemblyBuffer) GC(now time.Time, lifetime time.Duration) {
	for k, pb := range rb.m {
		if now.Sub(pb.created) >= lifetime {
			delete(rb.m, k)
		}
	}
}

// Len 当前待重组包数(测试 / 观测用)。
func (rb *ReassemblyBuffer) Len() int { return len(rb.m) }

// IsEmpty 是否无待重组包。
func (rb *ReassemblyBuffer) IsEmpty() bool { return len(rb.m) == 0 }
