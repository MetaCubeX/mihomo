// datagram_header_test.go —— DatagramHeader + Fragment + ReassemblyBuffer self-test。
// 镜像 Rust udp.rs:517-748 测试,逐项对应(四校验 / 乱序 / 幂等 / GC / 路径决策)。

package client

import (
	"bytes"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// dgAddr 测试地址 8.8.8.8:53(对照 Rust udp.rs:469 addr())。
func dgAddr() wire.Addr {
	return wire.Addr{Type: wire.AddrTypeIPv4, IPv4: [4]byte{8, 8, 8, 8}, Port: 53}
}

// TestDatagramHeaderFirstFragRoundtrip 首片 header(带 Addr)+ payload round-trip。
func TestDatagramHeaderFirstFragRoundtrip(t *testing.T) {
	addr := dgAddr()
	h := DatagramHeader{AssocID: 1, PktID: 2, FragTotal: 1, FragID: 0, Size: 5, Addr: &addr}
	wire_, err := h.EncodeWithPayload([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	h2, frag, err := DecodeDatagramHeader(wire_)
	if err != nil {
		t.Fatal(err)
	}
	if !dgHdrEqual(h, h2) {
		t.Fatalf("header 不一致: %+v != %+v", h2, h)
	}
	if !bytes.Equal(frag, []byte("hello")) {
		t.Fatal("frag payload 不一致")
	}
}

// TestDatagramHeaderNonFirstFrag0xff 非首片 ADDR 占位 0xff;FIXED_LEN 后第 1 字节必 0xff。
func TestDatagramHeaderNonFirstFrag0xff(t *testing.T) {
	h := DatagramHeader{AssocID: 1, PktID: 2, FragTotal: 3, FragID: 1, Size: 100, Addr: nil}
	wire_, err := h.EncodeWithPayload([]byte("chunk"))
	if err != nil {
		t.Fatal(err)
	}
	if wire_[DatagramHeaderFixedLen] != AddrTypeNone {
		t.Fatalf("非首片占位须 0xff, 得 0x%02x", wire_[DatagramHeaderFixedLen])
	}
	h2, frag, err := DecodeDatagramHeader(wire_)
	if err != nil {
		t.Fatal(err)
	}
	if !dgHdrEqual(h, h2) {
		t.Fatalf("header 不一致")
	}
	if !bytes.Equal(frag, []byte("chunk")) {
		t.Fatal("frag payload 不一致")
	}
	if h2.Addr != nil {
		t.Fatal("非首片 addr 须 nil")
	}
}

// TestDatagramHeaderBadMarkerAndTrunc 非首片标真实 atype(非 0xff)→ 畸形;< 8B → 截断。
func TestDatagramHeaderBadMarkerAndTrunc(t *testing.T) {
	// 非首片但标 atype=ipv4(0x01)→ ErrDgBadMarker。
	bad := []byte{
		0x00, 0x01, // assoc
		0x00, 0x02, // pkt
		0x03,       // frag_total
		0x01,       // frag_id(非首片)
		0x00, 0x64, // size=100
		0x01, // 应是 0xff,却给 atype=ipv4
	}
	if _, _, err := DecodeDatagramHeader(bad); err == nil {
		t.Fatal("非首片标真实 atype 须拒")
	}
	// 截断(< 8B)。
	if _, _, err := DecodeDatagramHeader(make([]byte, 4)); err == nil {
		t.Fatal("< 8B 须拒")
	}
}

// TestFragmentSmallSingleFrag 小 payload → 单片。
func TestFragmentSmallSingleFrag(t *testing.T) {
	addr := dgAddr()
	frags, err := Fragment(1, 7, &addr, []byte("hi"), 1200)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 1 {
		t.Fatalf("须单片, 得 %d", len(frags))
	}
	if frags[0].H.FragTotal != 1 || frags[0].H.FragID != 0 {
		t.Fatalf("frag_total/id 错: %d/%d", frags[0].H.FragTotal, frags[0].H.FragID)
	}
	if !bytes.Equal(frags[0].Payload, []byte("hi")) {
		t.Fatal("payload 不一致")
	}
}

// TestFragmentLargeThenReassemble 3000B payload,maxPlain=1100 → 多片;逆序到达重组须还原原文。
func TestFragmentLargeThenReassemble(t *testing.T) {
	addr := dgAddr()
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i)
	}
	frags, err := Fragment(1, 7, &addr, payload, 1100)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) <= 1 {
		t.Fatal("须切多片")
	}
	fragTotal := frags[0].H.FragTotal
	if int(fragTotal) != len(frags) {
		t.Fatalf("frag_total %d != 片数 %d", fragTotal, len(frags))
	}
	for _, fr := range frags {
		if fr.H.FragTotal != fragTotal {
			t.Fatal("所有片 frag_total 须一致")
		}
		if fr.H.Size != 3000 {
			t.Fatalf("size 须 3000, 得 %d", fr.H.Size)
		}
	}

	// 逆序到达(非首片先到,首片最后到)→ 重组须还原。
	now := time.Now()
	rb := NewReassemblyBuffer()
	var got *wire.Addr
	var data []byte
	complete := false
	for i := len(frags) - 1; i >= 0; i-- {
		fr := frags[i]
		// Insert 持有 frag 副本(内部 copy),可直接传 fr.Payload。
		a, p, done, err := rb.Insert(fr.H, fr.Payload, now)
		if err != nil {
			t.Fatalf("insert frag %d: %v", fr.H.FragID, err)
		}
		if done {
			got, data, complete = a, p, true
		}
	}
	if !complete {
		t.Fatal("须集齐完成")
	}
	if *got != addr {
		t.Fatalf("重组 addr 不一致: %+v != %+v", *got, addr)
	}
	if !bytes.Equal(data, payload) {
		t.Fatal("重组 payload 不一致")
	}
}

// TestFragmentEmptyPayload 空 payload → 单空片(size=0)。
func TestFragmentEmptyPayload(t *testing.T) {
	addr := dgAddr()
	frags, err := Fragment(1, 7, &addr, nil, 1200)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 1 || len(frags[0].Payload) != 0 || frags[0].H.Size != 0 {
		t.Fatalf("空 payload 须单片空, got %+v", frags[0])
	}
}

// TestFragmentBudgetTooSmall max_plain 容不下首片 header → Err。
func TestFragmentBudgetTooSmall(t *testing.T) {
	addr := dgAddr()
	if _, err := Fragment(1, 7, &addr, []byte("x"), 5); err == nil {
		t.Fatal("max_plain 容不下 header 须 Err")
	}
}

// TestReassemblyRuleViolations Rule 1(frag_id>=frag_total)/ Rule 3(首片缺 addr / 非首片带 addr)。
func TestReassemblyRuleViolations(t *testing.T) {
	now := time.Now()
	rb := NewReassemblyBuffer()

	// Rule 1:frag_id >= frag_total。
	bad := DatagramHeader{AssocID: 1, PktID: 1, FragTotal: 1, FragID: 5, Size: 0, Addr: nil}
	if _, _, _, err := rb.Insert(bad, nil, now); err == nil {
		t.Fatal("frag_id >= frag_total 须 Err")
	}

	// Rule 3:首片缺 addr。
	bad2 := DatagramHeader{AssocID: 1, PktID: 2, FragTotal: 1, FragID: 0, Size: 0, Addr: nil}
	if _, _, _, err := rb.Insert(bad2, nil, now); err == nil {
		t.Fatal("首片缺 addr 须 Err")
	}

	// Rule 3:非首片带 addr。
	addr := dgAddr()
	bad3 := DatagramHeader{AssocID: 1, PktID: 3, FragTotal: 2, FragID: 1, Size: 0, Addr: &addr}
	if _, _, _, err := rb.Insert(bad3, nil, now); err == nil {
		t.Fatal("非首片带 addr 须 Err")
	}
}

// TestReassemblyDuplicateIdempotent 重复投同一片不报错、不累加,最终仍正确完成(UDP 可重传)。
func TestReassemblyDuplicateIdempotent(t *testing.T) {
	addr := dgAddr()
	payload := bytes.Repeat([]byte{42}, 2000)
	frags, err := Fragment(9, 3, &addr, payload, 1000)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rb := NewReassemblyBuffer()
	var data []byte
	complete := false
	// 投两遍(第二遍 buffer 已 remove → 视新包,集齐再完成)。
	for pass := 0; pass < 2; pass++ {
		for _, fr := range frags {
			a, p, done, err := rb.Insert(fr.H, fr.Payload, now)
			if err != nil {
				t.Fatalf("pass %d frag %d: %v", pass, fr.H.FragID, err)
			}
			if done {
				_ = a
				data, complete = p, true
			}
		}
	}
	if !complete || !bytes.Equal(data, payload) {
		t.Fatal("重复投须仍正确完成")
	}
}

// TestReassemblyFragTotalMismatch 同 pkt_id 两片 frag_total 不一致 → Rule 2 冲突 Err。
func TestReassemblyFragTotalMismatch(t *testing.T) {
	addr := dgAddr()
	now := time.Now()
	rb := NewReassemblyBuffer()
	h1 := DatagramHeader{AssocID: 1, PktID: 5, FragTotal: 3, FragID: 0, Size: 100, Addr: &addr}
	h2 := DatagramHeader{AssocID: 1, PktID: 5, FragTotal: 2, FragID: 1, Size: 100, Addr: nil}
	if _, _, done, err := rb.Insert(h1, make([]byte, 34), now); err != nil || done {
		t.Fatalf("h1 应未集齐通过: %v done=%v", err, done)
	}
	if _, _, _, err := rb.Insert(h2, make([]byte, 50), now); err == nil {
		t.Fatal("frag_total 不一致 须 Err")
	}
}

// TestReassemblyGCEvictsStale 超期未集齐包被 GC 清(对照 Rust reassembly_gc_evicts_stale)。
func TestReassemblyGCEvictsStale(t *testing.T) {
	addr := dgAddr()
	now := time.Now()
	rb := NewReassemblyBuffer()
	h := DatagramHeader{AssocID: 1, PktID: 1, FragTotal: 2, FragID: 0, Size: 100, Addr: &addr}
	if _, _, _, err := rb.Insert(h, make([]byte, 50), now); err != nil {
		t.Fatal(err)
	}
	if rb.Len() != 1 {
		t.Fatalf("应 1 个待重组包, got %d", rb.Len())
	}
	// 模拟超期:GC 时 now + lifetime 之后 → 清。
	rb.GC(now.Add(GcLifetime+time.Millisecond), GcLifetime)
	if !rb.IsEmpty() {
		t.Fatal("超期未集齐包须被 GC 清")
	}
}

// dgHdrEqual 比较 header(Addr 用指针,需解引用比对值)。
func dgHdrEqual(a, b DatagramHeader) bool {
	if a.AssocID != b.AssocID || a.PktID != b.PktID || a.FragTotal != b.FragTotal ||
		a.FragID != b.FragID || a.Size != b.Size {
		return false
	}
	if (a.Addr == nil) != (b.Addr == nil) {
		return false
	}
	if a.Addr != nil && *a.Addr != *b.Addr {
		return false
	}
	return true
}
