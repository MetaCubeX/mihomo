// relay_zerocopy_test.go —— L4 收尾 · B 批量合帧 + writev + buffer 复用 self-test(对照 Rust relay.rs ③ tests)。
//
// 三铁律:
//   - [TestPumpEncodeBatchRoundtrip]:大数据跨 batch 边界 round-trip + 写入次数 ≪ 帧数(批量合帧生效);空输入 EOF→TcpClose。
//   - [TestPumpDecodeFastWritevBatch]:快路多帧批量经**真 *net.TCPConn** 一次 net.Buffers.WriteTo 投递(走 writev 分支,
//     net/net.go:851-853 type-assert buffersWriter;*net.TCPConn 在 net 包内实现 writeBuffers)。Go 不可从客户包
//     观测 writev(net.buffersWriter 未导出方法包级私有,客户包类型无法满足)→ 改验 production sink 路径正确。
//   - [TestPumpDecodeMaxAeadBodyFrame]:max AEAD 帧(body = payload+TAG = 65535)round-trip(pumpDecodeAead + bodyBuf 复用)。
//
// 对照 Rust relay.rs ③ tests(pump_encode_batch_roundtrip / pump_decode_fast_writev_batch / pump_decode_max_aead_body_frame)。
// 密钥确定性填充(非生产,永不复用到生产);测试只 bytes.Equal / 计数,不打 raw 密钥。

package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// countSink 记累积字节 + Write 次数(encode 批量合帧测试:写入次数 ≪ 帧数 = 批量生效;对照 Rust VecSink)。
type countSink struct {
	buf    []byte
	writes int
}

func (s *countSink) Write(b []byte) (int, error) {
	s.buf = append(s.buf, b...)
	s.writes++
	return len(b), nil
}

// 注:Go 无法从 net 包外观测 writev 是否触发 —— net.buffersWriter.writeBuffers 是未导出方法,**包级私有**
// (net 包的 writeBuffers ≠ client 包的 writeBuffers),故客户包类型结构化无法满足 net.buffersWriter;
// net.Buffers.WriteTo 对客户包 io.Writer 恒走 fallback 逐块 Write。因此 writev 铁证只能用**真 *net.TCPConn**
// (它在 net 包内实现 writeBuffers → net.Buffers.WriteTo 走 writev 分支,net/net.go:851-853)做 sink,验证
// 多帧批量经 production writev 路径正确投递。writev 的 syscall 合并由 net 源码保证(type-assert buffersWriter),
// stream socket 读侧不可观测 syscall 边界,故不单独断言合并度(Rust ProbeSink 因 Rust 公开 poll_write_vectored
// 才可记 IoSlice 数;Go 刻意隐藏,只能验路径正确)。

// TestPumpEncodeBatchRoundtrip 快路 + 伪装路各:大数据跨 relayEncodeBatch 边界(多批)+ 尾部短读 → round-trip
// 正确性 + 写入次数 ≪ 帧数(批量合帧生效);空输入直 EOF→TcpClose。对照 Rust pump_encode_batch_roundtrip。
func TestPumpEncodeBatchRoundtrip(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		// 空输入:encode 首读即 EOF → 不攒帧 → 直接发 TcpClose;decode 收 close 即退,out 空。
		k, n := testKeyNonce(0xB0)
		tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: true}
		rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: true}
		sink := &countSink{}
		if err := pumpEncode(&tx, bytes.NewReader(nil), sink); !errors.Is(err, io.EOF) {
			t.Fatalf("pumpEncode 空输入: got %v, want io.EOF", err)
		}
		var out bytes.Buffer
		if err := pumpDecode(&rx, bytes.NewReader(sink.buf), &out); !errors.Is(err, io.EOF) {
			t.Fatalf("pumpDecode: got %v, want io.EOF", err)
		}
		if out.Len() != 0 {
			t.Fatalf("空输入应产空 out, got %d bytes", out.Len())
		}
	})

	for _, noInner := range []bool{true, false} {
		t.Run(armName(noInner), func(t *testing.T) {
			k, n := testKeyNonce(0xB0)
			tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: noInner}
			rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: noInner}

			// 大数据 > 3.5×relayEncodeBatch:跨多个满批(每批 batchFrames 帧)+ 尾部短读(< relayChunk)触发 flush。
			bulk := relayEncodeBatch*3 + 12345
			data := make([]byte, bulk)
			for i := range data {
				data[i] = byte(i)
			}

			sink := &countSink{}
			// encode:data → sink(返 io.EOF,已发 TcpClose)。
			if err := pumpEncode(&tx, bytes.NewReader(data), sink); !errors.Is(err, io.EOF) {
				t.Fatalf("pumpEncode: got %v, want io.EOF", err)
			}
			// 批量不变量:写入次数 ≪ 帧数(bulk/relayChunk 帧 → 每 batchFrames 帧合 1 Write)。
			framesApprox := (bulk + relayChunk - 1) / relayChunk
			if sink.writes >= framesApprox {
				t.Errorf("批量合帧未生效:写入 %d 次 ≈ 帧数 %d(期望写入 ≪ 帧数)", sink.writes, framesApprox)
			}
			t.Logf("批量合帧:%d 字节 → ~%d 帧 → %d 次 Write(批量前应 ≈ 帧数)", bulk, framesApprox, sink.writes)

			// decode:sink.buf → out,比对原 data(含 TcpClose → pumpDecode 返 io.EOF)。
			var out bytes.Buffer
			if err := pumpDecode(&rx, bytes.NewReader(sink.buf), &out); !errors.Is(err, io.EOF) {
				t.Fatalf("pumpDecode: got %v, want io.EOF", err)
			}
			if !bytes.Equal(out.Bytes(), data) {
				t.Fatalf("roundtrip 失配:got %d bytes, want %d", out.Len(), len(data))
			}
		})
	}
}

// TestPumpDecodeFastWritevBatch 快路批量 writev 路径铁证:2 满帧 + 1 小帧 → pumpDecodeFast 攒 3 帧 body 进
// 单 net.Buffers(len=3)→ WriteTo(local *net.TCPConn)走 writev 分支(net/net.go:851-853 type-assert buffersWriter,
// *net.TCPConn 在 net 包内实现 writeBuffers)→ 接收侧收齐全部字节 = production writev 路径正确。
//
// 满帧 blen==relayChunk 不触发 break readBatch(攒批),小帧 blen<relayChunk 触发 break → 一次 flushRanges 多帧。
// 对照 Rust pump_decode_fast_writev_batch(Rust ProbeSink 记 IoSlice 数 >1;Go 不可观,改验真 socket 路径)。
func TestPumpDecodeFastWritevBatch(t *testing.T) {
	k, n := testKeyNonce(0xB1)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: true} // 快路
	rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: true}

	full := bytes.Repeat([]byte{0x11}, relayChunk)
	small := bytes.Repeat([]byte{0x22}, 100)
	// 逐帧 EncryptFrameInto 拼接(独立 out 避免互清;ctr 依次推进 0/1/2)。
	var frames []byte
	for _, fr := range [][]byte{
		append([]byte(nil), full...),
		append([]byte(nil), full...),
		small,
	} {
		var out []byte
		if _, e := tx.EncryptFrameInto(wire.FrameTCPData, fr, &out); e != nil {
			t.Fatal(e)
		}
		frames = append(frames, out...)
	}
	// 不放 TcpClose:小帧那批先 writev,下轮顶 src 干净 EOF 退(测批边界 EOF,非 close 级联)。

	// 真 TCP 对:local = *net.TCPConn(production sink 类型,走 writev 分支)。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type recvResult struct {
		got []byte
		err error
	}
	resCh := make(chan recvResult, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			resCh <- recvResult{nil, err}
			return
		}
		defer c.Close()
		got, err := io.ReadAll(c)
		resCh <- recvResult{got, err}
	}()

	local, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer local.Close()

	// pumpDecodeFast 写 local(*net.TCPConn)→ flushRanges → net.Buffers.WriteTo 走 writev 分支。
	if err := pumpDecodeFast(&rx, bytes.NewReader(frames), local); !errors.Is(err, io.EOF) {
		t.Fatalf("pumpDecodeFast: got %v, want io.EOF", err)
	}
	// 关 local 触发接收侧 io.ReadAll EOF 返回。
	if err := local.Close(); err != nil {
		t.Fatalf("close local: %v", err)
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("接收侧读: %v", res.err)
	}
	expect := make([]byte, 0, len(full)*2+len(small))
	expect = append(expect, full...)
	expect = append(expect, full...)
	expect = append(expect, small...)
	if !bytes.Equal(res.got, expect) {
		t.Fatalf("writev 批量数据失配:got %d bytes, want %d", len(res.got), len(expect))
	}
	t.Logf("快路 writev 路径:3 帧(2 满 + 1 小)经 *net.TCPConn 一次 net.Buffers.WriteTo 投递 %d 字节正确", len(expect))
}

// TestPumpDecodeMaxAeadBodyFrame max-size AEAD 帧(body = payload+TAG = 65535 = u16::MAX)round-trip 通过
// pumpDecodeAead(伪装路,per-frame Write + bodyBuf 复用)。钉:body buffer 须容 MaxFrameBodyLen(漏算 +TAG 会越界)。
// 对照 Rust pump_decode_max_aead_body_frame。
func TestPumpDecodeMaxAeadBodyFrame(t *testing.T) {
	k, n := testKeyNonce(0xB2)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: false} // 伪装路(AEAD)
	rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: false}

	payload := bytes.Repeat([]byte{0xAB}, wire.MaxPayloadLen) // body 将 = MaxPayloadLen + TAG = 65535 = u16::MAX
	var frame []byte
	if _, e := tx.EncryptFrameInto(wire.FrameTCPData, payload, &frame); e != nil {
		t.Fatal(e)
	}
	// sanity:AEAD 路 max 帧总长 = HEADER + MaxPayloadLen + TAG。
	if want := wire.FrameHeaderLen + wire.MaxPayloadLen + wire.AEADTagLen; len(frame) != want {
		t.Fatalf("max AEAD 帧长 %d != %d", len(frame), want)
	}

	var out bytes.Buffer
	// 读数据帧 → 循环读下一帧首字节 → src EOF → ReadFrameInto 返 io.EOF → pumpDecodeAead 返 io.EOF。
	if err := pumpDecode(&rx, bytes.NewReader(frame), &out); !errors.Is(err, io.EOF) {
		t.Fatalf("pumpDecode: got %v, want io.EOF", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("max AEAD 帧 payload 失配:got %d bytes, want %d", out.Len(), len(payload))
	}
}
