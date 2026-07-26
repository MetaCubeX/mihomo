// padding_test.go —— ADR-016 PADDING 塑形 self-test(镜像 Rust padding.rs + relay.rs padding 测)。
//
// 三组:
//   - scheme / prng 单元:[TestTargetWithinBand]/[TestTargetZeroAfterStop]/[TestPrngFillNondeterministic]/[TestPrngGenRangeEdges]
//     (对照 Rust padding.rs tests)。
//   - decode 盲丢:[TestPaddingFrameDiscardedFast]/[TestPaddingFrameDiscardedAead](PADDING+TcpData → out 只收 TcpData body)。
//   - encode 注入 + round-trip:[TestPaddingEncodeInjectsFirstN](快路 + caps PADDING + 短读 → 前 stopN record 各注
//     1 PADDING 帧,之后无;对照 Rust padding_encode_injects_first_n)+ [TestPaddingEncodeRoundtrip](含 padding 编 → decode 还原原 data)。
//
// 密钥确定性填充(非生产,永不复用);测试只 bytes.Equal / 计数,不打 raw 密钥/帧体明文(§5.4)。

package client

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// frameTypes 逐帧解析明文帧头(AAD:type+len+ctr;body 跳 Len 字节)返回帧类型序列。
// 不解密(只需 type 计数);快路 body 明文、伪装路 body 密文但 Len 仍是 body 长度 → 跳过即可。
func frameTypes(b []byte) []wire.FrameType {
	var types []wire.FrameType
	for len(b) >= wire.FrameHeaderLen {
		hdr, err := wire.ParseHeader(b[:wire.FrameHeaderLen])
		if err != nil {
			break
		}
		types = append(types, hdr.Type)
		advance := wire.FrameHeaderLen + int(hdr.Len)
		if advance > len(b) {
			break
		}
		b = b[advance:]
	}
	return types
}

// chunkedReader 每次 Read 最多 yield chunk 字节(模拟交互短读;对照 Rust ChunkedReader)。
type chunkedReader struct {
	data  []byte
	off   int
	chunk int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := r.chunk
	if n > len(p) {
		n = len(p)
	}
	rem := len(r.data) - r.off
	if n > rem {
		n = rem
	}
	copy(p, r.data[r.off:r.off+n])
	r.off += n
	return n, nil
}

// TestTargetWithinBand i<stopN:target 落 [lo,hi] 闭区间(每带 50 抽样全命中;对照 Rust target_within_band)。
func TestTargetWithinBand(t *testing.T) {
	scheme := defaultPaddingScheme()
	prng := newPrngFromEntropy()
	for i, band := range httpsLikeBands {
		for j := 0; j < 50; j++ {
			v := scheme.target(i, prng)
			if v < band.lo || v > band.hi {
				t.Fatalf("target %d 越出带 [%d,%d](i=%d,j=%d)", v, band.lo, band.hi, i, j)
			}
		}
	}
}

// TestTargetZeroAfterStop i>=stopN → 0(不塑形,稳态直出;对照 Rust target_zero_after_stop)。
func TestTargetZeroAfterStop(t *testing.T) {
	scheme := defaultPaddingScheme()
	prng := newPrngFromEntropy()
	for i := stopN; i < stopN+5; i++ {
		if v := scheme.target(i, prng); v != 0 {
			t.Fatalf("i=%d ≥ stopN 应返 0,got %d", i, v)
		}
	}
}

// TestPrngFillNondeterministic 两独立 OS 熵 seed → 不同输出(反静态指纹;对照 Rust prng_fill_nondeterministic)。
func TestPrngFillNondeterministic(t *testing.T) {
	a := newPrngFromEntropy()
	b := newPrngFromEntropy()
	ba := make([]byte, 4096)
	bb := make([]byte, 4096)
	a.fill(ba)
	b.fill(bb)
	if bytes.Equal(ba, bb) {
		t.Fatal("两 per-conn PRNG 序列应不同(反静态 md5 指纹)")
	}
}

// TestPrngGenRangeEdges lo>=hi → 返 lo(防 Intn(0) panic);正常区间内值合法(对照 Rust prng_gen_range_edges)。
func TestPrngGenRangeEdges(t *testing.T) {
	prng := newPrngFromEntropy()
	if v := prng.genRange(5, 5); v != 5 {
		t.Fatalf("lo==hi → 返 lo,got %d", v)
	}
	if v := prng.genRange(5, 3); v != 5 {
		t.Fatalf("lo>hi → 返 lo,got %d", v)
	}
	v := prng.genRange(100, 200)
	if v < 100 || v > 200 {
		t.Fatalf("genRange 值须落闭区间 [100,200],got %d", v)
	}
}

// TestBulkShapeFromParsesEnvValue 纯函数解析 SPEEDCAT_BULK_SHAPE 值(对照 Rust bulk_shape_from_parses_env_value)。
// 不触全局 env / 不依赖 sync.Once 缓存(纯函数单测,免并发 flake;bulkShapeEnv 的进程级缓存语义同 padding_disabled_env 不单测)。
func TestBulkShapeFromParsesEnvValue(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},  // 未设 / 空串 → 不切片(默认 OFF)。
		{"0", false}, // 显式 "0" → 不切片。
		{"1", true},  // 任意非空非 "0" → 启用切片。
		{"yes", true},
		{"true", true},
		{"anything-nonzero", true},
	}
	for _, c := range cases {
		if got := bulkShapeFrom(c.in); got != c.want {
			t.Fatalf("bulkShapeFrom(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestPaddingFrameDiscardedFast 快路:PADDING + TcpData 两帧 → pumpDecodeFast out 只收 TcpData body(PADDING 盲丢,无 Wire error)。
// 对照 Rust padding_frame_discarded_fast。
func TestPaddingFrameDiscardedFast(t *testing.T) {
	k, n := testKeyNonce(0xC0)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: true} // 快路
	rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: true}

	payload := []byte("speedcat-data-after-padding")
	// 先 PADDING 帧(随机 body),再 TcpData 帧(payload)。
	var frames []byte
	var padOut []byte
	if _, e := tx.EncryptFrameInto(wire.FramePadding, []byte("random-padding-bytes"), &padOut); e != nil {
		t.Fatal(e)
	}
	frames = append(frames, padOut...)
	var dataOut []byte
	if _, e := tx.EncryptFrameInto(wire.FrameTCPData, payload, &dataOut); e != nil {
		t.Fatal(e)
	}
	frames = append(frames, dataOut...)

	var out bytes.Buffer
	// 帧后无 Tcpclose → 读完 frames 首字节 EOF → pumpDecodeFast 批边界干净 EOF 返 io.EOF。
	if err := pumpDecode(&rx, bytes.NewReader(frames), &out); !errors.Is(err, io.EOF) {
		t.Fatalf("pumpDecode: got %v, want io.EOF(PADDING 应被消费不报错)", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("out 应只含 TcpData body(PADDING 被丢):got %d bytes,want %d", out.Len(), len(payload))
	}
}

// TestPaddingFrameDiscardedAead 伪装路:PADDING + TcpData → pumpDecodeAead out 只收 TcpData body(对称消费)。
func TestPaddingFrameDiscardedAead(t *testing.T) {
	k, n := testKeyNonce(0xC1)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: false} // 伪装路(AEAD)
	rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: false}

	payload := []byte("aead-path-data-after-padding")
	var frames []byte
	var padOut []byte
	if _, e := tx.EncryptFrameInto(wire.FramePadding, []byte("random-pad"), &padOut); e != nil {
		t.Fatal(e)
	}
	frames = append(frames, padOut...)
	var dataOut []byte
	if _, e := tx.EncryptFrameInto(wire.FrameTCPData, payload, &dataOut); e != nil {
		t.Fatal(e)
	}
	frames = append(frames, dataOut...)

	var out bytes.Buffer
	if err := pumpDecode(&rx, bytes.NewReader(frames), &out); !errors.Is(err, io.EOF) {
		t.Fatalf("pumpDecode: got %v, want io.EOF", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("out 应只含 TcpData body:got %d bytes,want %d", out.Len(), len(payload))
	}
}

// TestPaddingEncodeInjectsFirstN 快路 + caps PADDING + 交互短读:前 stopN 条 record 各注 1 PADDING 帧(凑 target),
// stopN 后短读不再注 PADDING(退原启发式)。对照 Rust padding_encode_injects_first_n。
func TestPaddingEncodeInjectsFirstN(t *testing.T) {
	k, n := testKeyNonce(0xC2)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: true, padding: true} // 快路 + PADDING on
	rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: true}

	// 交互短读:每读 10 字节(< relayChunk → short_read 触发 flush),喂 stopN+5 次短读。
	chunkSize := 10
	totalReads := stopN + 5
	data := bytes.Repeat([]byte{0x5A}, chunkSize*totalReads)
	src := &chunkedReader{data: data, chunk: chunkSize}

	sink := &countSink{}
	if err := pumpEncode(&tx, src, sink); !errors.Is(err, io.EOF) {
		t.Fatalf("pumpEncode: got %v, want io.EOF", err)
	}

	types := frameTypes(sink.buf)
	var pad, dataFrames int
	for _, ft := range types {
		switch ft {
		case wire.FramePadding:
			pad++
		case wire.FrameTCPData:
			dataFrames++
		}
	}
	// 前 stopN 短读各注 1 PADDING 凑 target;stopN 后退原启发式(短读 flush 但不注 padding)。
	if pad != stopN {
		t.Fatalf("PADDING 帧数 = %d, want %d(前 stopN record 各 1 帧)", pad, stopN)
	}
	// TcpData 帧数 = 短读次数(每次短读 1 帧 TcpData;不含尾 TcpClose,frameTypes 也计到 close)。
	if dataFrames != totalReads {
		t.Fatalf("TcpData 帧数 = %d, want %d", dataFrames, totalReads)
	}
	t.Logf("PADDING 塑形:%d 短读 → 前 %d record 各注 1 PADDING 帧(stopN 后 %d record 无 padding)",
		totalReads, stopN, totalReads-stopN)

	// round-trip:含 padding 编 → decode 还原原 data(PADDING 帧被盲丢,data 完整)。
	var out bytes.Buffer
	if err := pumpDecode(&rx, bytes.NewReader(sink.buf), &out); !errors.Is(err, io.EOF) {
		t.Fatalf("pumpDecode roundtrip: got %v, want io.EOF", err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("roundtrip 失配:got %d bytes,want %d", out.Len(), len(data))
	}
}

// TestPaddingEncodeRoundtripCapsOff caps PADDING 未协商(padding=false)→ encode 不注 PADDING(frameTypes 无 Padding),
// round-trip 仍正确(对照 Rust padding_encode_bulk_no_padding 的「caps off 不塑形」语义)。
func TestPaddingEncodeRoundtripCapsOff(t *testing.T) {
	k, n := testKeyNonce(0xC3)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: true, padding: false} // 快路 + PADDING off
	rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: true}

	data := bytes.Repeat([]byte{0x77}, 1000)
	sink := &countSink{}
	if err := pumpEncode(&tx, bytes.NewReader(data), sink); !errors.Is(err, io.EOF) {
		t.Fatalf("pumpEncode: got %v, want io.EOF", err)
	}
	for _, ft := range frameTypes(sink.buf) {
		if ft == wire.FramePadding {
			t.Fatal("caps PADDING off 不应产 PADDING 帧")
		}
	}
	var out bytes.Buffer
	if err := pumpDecode(&rx, bytes.NewReader(sink.buf), &out); !errors.Is(err, io.EOF) {
		t.Fatalf("pumpDecode: got %v, want io.EOF", err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("roundtrip 失配:got %d bytes,want %d", out.Len(), len(data))
	}
}
