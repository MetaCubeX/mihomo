// relay.go —— TCP relay pump:把本地应用字节流 ↔ speedcat 连接双向桥接(镜像 Rust relay.rs)。
//
// 两 goroutine 并发(对照 Rust tokio::try_join!):
//   - [pumpEncode]:读 local 明文 → 封 TcpData 帧写 conn。批量合帧(≤ batchFrames 帧/Write)+ 快路零拷贝
//     (body 直读进 batch 头后位置,头就地覆写)。local EOF → 发 TcpClose(空)+ 返 io.EOF。
//   - [pumpDecode]:读 conn 帧 → 解密 → 写 local。快路 net.Buffers writev(多帧 body 合一次 WriteTo);
//     伪装路 per-frame Write(AEAD body 须解密进复用 out → 跨帧攒 buffer 会别名,不批量)。
//
// # 批量 + writev + 零拷贝(L4 收尾 B,镜像 Rust relay.rs ③ issue #1)
//
// 对照 Rust relay.rs:59-67,78-160,173-408 逐段。三处显性收益(热路径):
//   - **encode 批量合帧**:攒 ≤ batchFrames 帧进大 batch buffer 一次 Write(减 conn 写 syscall 密度,③(a))。
//     快路 body **直读进 batch 头后位置** + [SessionTx.sealFrameHeaderFast] 就地写头 → 免 EncryptFrameInto 的
//     buf→out memcpy(③(c),零拷贝)。伪装路读进 buf + EncryptFrameInto 追加进 batch(1 拷贝;AEAD body 须 Seal
//     出密文,非原位可封)。
//   - **decode 快路 writev**:大 ct buffer 攒 ≤ batchFrames 帧 body,记 (start,end) range,net.Buffers 一次
//     WriteTo(local) → local 是 *net.TCPConn/*net.UnixConn 时走 writev(单 syscall 合并多 body,③(b));快路 body
//     原位(DecryptFrame 零拷贝返 body 切片)。
//   - **buffer 复用**:batch / ct / bodyBuf / out 循环外一次 alloc 复用(0 per-frame alloc;对照 Rust
//     vec![0u8; cap] 一次 init)。**不用 sync.Pool**:per-pump 本地复用即够(镜像 Rust per-pump Vec);
//     sync.Pool(跨 pump 共享)留 P5 高并发(<1 GB / 10 kconn 门,Rust relay.rs:41 同款注记)。
//
// # 半关级联(对照 Rust relay.rs:410-437 注释)
//
// 任一向 EOF 经 TcpClose 帧向对端传播,对端 decode 收到亦退。关键:**编码向(local→conn)正常 EOF 不解阻塞**
// —— 此时对端响应尚未读完,强行关 conn 会截断响应(如 HTTP 请求后 app shutdown 写但仍在读响应);让解码向
// 继续读 conn 直到对端 TcpClose。**解码向(conn→local)返回则关 local** —— 对端不再发数据,编码向读 local
// 无意义,关之解阻塞。出错则两端同关(abort)。
//
// # 延迟启发式(对照 Rust relay.rs 模块头)
//
// encode「满批 OR 短读」flush、decode「满批 OR 小帧」writev —— bulk 全读 / 满帧攒批降 syscall 密度;交互短读 /
// 小帧立即 flush 不滞留(proxy 实时性)。bulk 突发尾的最后一满帧会被攒到下帧 / EOF 才出(bulk 不敏感);交互
// 小帧不滞留。
//
// # 内存注(对照 Rust relay.rs:39-41)
//
// 每 active relay encode batch(~320 KiB)+ decode ct(~262 KiB)≈ ~580 KiB/conn。P2a 单连 / bench 无碍;P5
// (<1 GB / 10 kconn)调小 batchFrames 或改共享 buffer 池(留 P5)。
//
// # 冷热路径
//
// relay 是热路径。**panic-free**(被 mihomo import 的库:AEAD/decode 错返 error)。AEAD / 帧编解码内禁日志。

package client

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// ErrPeer 对端发来 Error 帧(如服务端 dial 目标失败),payload 为错误描述(对照 Rust Error::Peer,MED-1)。
var ErrPeer = errors.New("client/relay: 对端报告错误")

// ErrUnexpectedFrame 数据泵收到非数据帧(协议违规,fail-loud;对照 Rust pump_decode Error::Wire)。
var ErrUnexpectedFrame = errors.New("client/relay: 数据泵收到非预期帧类型")

// relayChunk 单次从 local 读取后封帧的上限(payload 字节;对照 Rust RELAY_CHUNK = MAX_PAYLOAD_LEN)。
const relayChunk = wire.MaxPayloadLen

// batchFrames 批量合帧的帧数上限(encode batch / decode ct 各攒 ≤ 此数帧后一次写出;对照 Rust BATCH_FRAMES=4)。
// tunable:大 → syscall 密度更低(throughput);小 → per-conn 内存更低 + 突发尾滞留更短。4 帧 ≈ 256 KiB/批是
// loopback bulk 的甜点(syscall 节省趋饱和,内存可接受)。P5 高并发可调小。
const batchFrames = 4

// relayEncodeBatch encode 攒批字节上限(~256 KiB;满此值即 Write,与「短读 flush」并列触发;对照 Rust ENCODE_BATCH)。
const relayEncodeBatch = relayChunk * batchFrames

// Relay 双向桥接 conn(speedcat 连接)↔ local(明文字节流,如 SOCKS5 拨号出的 TCP)。
// 阻塞至两向都结束(正常 EOF 级联 或 错误)。返回首个非良性错误(良性 = nil / io.EOF / net.ErrClosed)。
//
// conn / local 须支持并发 read+write(net.Conn / transport.Conn 天然支持;Go 无需像 Rust 那样 split 半)。
// 调用方(SOCKS5 handler)负责在 Relay 返回后 Close conn/local(本函数内仅按半关语义局部 Close 解阻塞)。
func Relay(tx *SessionTx, rx *SessionRx, conn, local io.ReadWriteCloser) error {
	encErr := make(chan error, 1)
	decErr := make(chan error, 1)
	go func() { encErr <- pumpEncode(tx, local, conn) }()
	go func() { decErr <- pumpDecode(rx, conn, local) }()

	var enc, dec error
	haveEnc, haveDec := false, false
	for !haveEnc || !haveDec {
		select {
		case enc = <-encErr:
			haveEnc = true
			// 编码向出错 = conn 坏 → 关两端解阻塞解码向;正常 EOF(io.EOF,已发 TcpClose)则不动,
			// 让解码向继续读对端响应(半关级联,见模块头)。
			if !errors.Is(enc, io.EOF) {
				_ = conn.Close()
				_ = local.Close()
			}
		case dec = <-decErr:
			haveDec = true
			// 解码向返回(对端 TcpClose 正常 / 错误):对端不再发 → 关 local 解阻塞编码向读。
			_ = local.Close()
			if !errors.Is(dec, io.EOF) {
				_ = conn.Close() // 出错 → 连 conn 也关(abort)。
			}
		}
	}
	// 返回首个非良性错误;皆良性(正常 EOF 级联 + 诱导的 closed)→ nil。
	if !isBenign(enc) {
		return enc
	}
	if !isBenign(dec) {
		return dec
	}
	return nil
}

// isBenign 良性错误 = 正常 EOF 或协调器诱导的「连接已关」(非真实故障)。
func isBenign(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

// pumpEncode 读 local 明文 → 封 TcpData 帧写 conn(加密向;对照 Rust pump_encode)。按快路/伪装路分发:
// 快路([pumpEncodeFast])批量合帧 + body 直读进 batch(零 memcpy);伪装路([pumpEncodeAead])批量合帧
// (EncryptFrameInto 追加进 batch,1 拷贝)。local EOF(io.EOF)→ 发 TcpClose(空)+ 返 io.EOF(正常半关)。
func pumpEncode(tx *SessionTx, local io.Reader, conn io.Writer) error {
	if tx.NoInnerAEAD() {
		return pumpEncodeFast(tx, local, conn)
	}
	return pumpEncodeAead(tx, local, conn)
}

// pumpEncodeFast 快路批量合帧 + 零拷贝(对照 Rust pump_encode fast 分支,relay.rs:106-145)。一次性满容 alloc
// batch(cap 容 relayEncodeBatch + 一帧余量)→ body 直读进头后位置、头就地覆写,0 per-frame alloc / 0 memcpy。
// 延迟启发式:满批 OR 短读 → Write(bulk 全读攒批;交互短读立即 flush 保实时)。
//
// **ADR-016 PADDING 塑形(快路 + caps PADDING):** 前 [stopN] 条 record 按分布带 target 早 flush + 交互短读补
// 一帧 PADDING 凑 target(消灭「代理发 tiny record」指纹);stopN 后稳态直出(零开销,ADR-005)。镜像 Rust
// relay.rs:102-199 逐段。塑形仅连接冷段(前 8 record);稳态 bulk pump 逐字不变。
func pumpEncodeFast(tx *SessionTx, local io.Reader, conn io.Writer) error {
	// cap 须容 relayEncodeBatch + 一帧余量(头 + chunk + tag),顶 check 据此防越界(对照 Rust relay.rs:85)。
	capBytes := relayEncodeBatch + wire.FrameHeaderLen + relayChunk + wire.AEADTagLen
	batch := make([]byte, capBytes)
	n := 0 // batch 逻辑长度(已攒字节数)。
	// ADR-016 塑形冷路径状态:scheme 近零成本构造;prng 仅 padActive 时 1 次 OS 熵冷 seed(~µs,per-conn)。
	// pumpEncodeFast 仅快路调用 → NoInnerAEAD 恒真,padActive = Padding()(快路 + 协商 PADDING)。
	padActive := tx.Padding()
	scheme := defaultPaddingScheme()
	var prngState *prng
	if padActive {
		prngState = newPrngFromEntropy()
	}
	shapedRecords := 0
	for {
		// 顶 check:剩余容不下头 + 最大 body(+tag)→ 先 flush(防越界,safety 兜底)。
		if n+wire.FrameHeaderLen+relayChunk+wire.AEADTagLen > capBytes {
			if _, we := conn.Write(batch[:n]); we != nil {
				return we
			}
			n = 0
		}
		// 快路:body 直读进 batch[n+7 .. n+7+relayChunk](切片长度自然封顶 body ≤ relayChunk)→ 0 memcpy
		// (原 buf→out 拷贝消除,③(c))。headroom [n..n+7] 留给帧头。
		bodyOff := n + wire.FrameHeaderLen
		rn, err := local.Read(batch[bodyOff : bodyOff+relayChunk])
		if rn > 0 {
			// 就地写帧头进 headroom(advance ctr + 7B AAD;快路 Len = payload 长度,无 tag;ctr 单一真源 advanceCtr)。
			if e := tx.sealFrameHeaderFast(wire.FrameTCPData, rn, batch[n:n+wire.FrameHeaderLen]); e != nil {
				return e
			}
			n += wire.FrameHeaderLen + rn
			shortRead := rn < relayChunk
			// 延迟启发式(模块头)+ ADR-016 PADDING 塑形。
			if padActive && shapedRecords < stopN {
				// 塑形(快路 + caps PADDING,前 stopN record):按分布带 target 早 flush + 短读补 PADDING 凑 target。
				// stopN 后整段退原启发式(稳态 bulk 逐字不变,ADR-005 零稳态开销)。
				target := scheme.target(shapedRecords, prngState)
				// bulk(n 已 >> target)→ 直接早 flush 造 ~target 量级 record;短读 → 进 flush 块(可能补 padding)。
				if n >= target || shortRead {
					// 交互短读且攒的明文 < target → 补一帧 PADDING(随机明文 body,快路无 tag)凑到 target,
					// 消灭「代理发 tiny record」指纹。n+7 >= target(bulk)时不补。pad = target-n-7。
					// **slice 安全不变量(对照 Rust debug_assert):** 补 padding 仅当 n+7 < target ≤ 1630,
					// 故 n+7+pad = target ≤ capBytes(顶 check 保 n 余量;target 量级远小于 256KiB batch)。
					if n+wire.FrameHeaderLen < target {
						pad := target - n - wire.FrameHeaderLen
						prngState.fill(batch[n+wire.FrameHeaderLen : n+wire.FrameHeaderLen+pad])
						// PADDING 帧头进 headroom [n..n+7](advance ctr + 7B AAD,ctr 单一真源)。
						if e := tx.sealFrameHeaderFast(wire.FramePadding, pad, batch[n:n+wire.FrameHeaderLen]); e != nil {
							return e
						}
						n += wire.FrameHeaderLen + pad
					}
					// ADR-016 §5 留后 → 落地:bulk 切片塑形(opt-in SPEEDCAT_BULK_SHAPE,默认 OFF)。
					// bulk 读(n >> target,非短读)+ opt-in → 按 target 切片循环 Write 造 N 条独立 ~target 量级 TLS
					// record(反 ~16401B bulk 指纹);冷段 stopN 切完后续退整段 Write(零稳态开销,ADR-005)。
					// **flush-per-record 风险(Go,中):** Go crypto/tls 对 sub-max-fragment Write 可能 coalesce(不像
					// rustls flush 排空 buffer)→ 切片 record 可能被合并。既有 Go 交互塑形(每 record 一次 conn.Write)
					// 已依赖 per-Write emission 并随 ADR-016 shipped —— 此风险非切片新引入,是 Go upload 方向既有 latent
					// (Probe 2 测的是 server→client=Rust 方向)。处置:本轮 tee harness 加测 client→server(Go)方向据实报。
					if bulkShapeEnv() && !shortRead && n > target {
						offset := 0
						// Phase 1:冷段切片 —— 前 stopN record 各 ~target(per-Write emission 造独立 TLS record)。
						for offset+target <= n && shapedRecords < stopN {
							if _, we := conn.Write(batch[offset : offset+target]); we != nil {
								return we
							}
							offset += target
							shapedRecords++
							if shapedRecords < stopN {
								target = scheme.target(shapedRecords, prngState)
							}
						}
						// Phase 2:余量(stopN 命中或余 < target)→ 整段 Write(稳态路径 unshaped;不增 shapedRecords)。
						if offset < n {
							if _, we := conn.Write(batch[offset:n]); we != nil {
								return we
							}
						}
						n = 0
					} else {
						// 原整段 Write(n 接近 target / 短读补 padding 后 / bulk_shape 未开 bulk 整段)。
						if _, we := conn.Write(batch[:n]); we != nil {
							return we
						}
						n = 0
						shapedRecords++
					}
				}
				// else(n < target 且非短读 = bulk 攒批中):不 flush,续读攒到 target → 下轮早 flush。
			} else if n >= relayEncodeBatch || shortRead {
				// 原启发式(stopN 后 / caps 未协商):满批 OR 短读 flush。
				// bulk 全读(=relayChunk)继续攒降 flush 密度;交互短读立即 flush 保 proxy 实时性。
				if _, we := conn.Write(batch[:n]); we != nil {
					return we
				}
				n = 0
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// flush 余帧(批量未满即 EOF)。
				if n > 0 {
					if _, we := conn.Write(batch[:n]); we != nil {
						return we
					}
					n = 0
				}
				// EOF → TcpClose(空 payload)通知对端流结束;关帧冷路径(1 次/连接),用 EncryptFrameInto(两路通用)。
				var closeFrame []byte
				if _, e := tx.EncryptFrameInto(wire.FrameTCPClose, nil, &closeFrame); e != nil {
					return e
				}
				if _, we := conn.Write(closeFrame); we != nil {
					return we
				}
				return io.EOF
			}
			return err
		}
	}
}

// pumpEncodeAead 伪装路批量合帧(对照 Rust pump_encode AEAD 分支,relay.rs:125-136)。读进 buf + EncryptFrameInto
// 追加进 batch(1 拷贝;AEAD body 须 Seal 出密文,非原位可封)。延迟启发式同 fast:满批 OR 短读 flush。
func pumpEncodeAead(tx *SessionTx, local io.Reader, conn io.Writer) error {
	buf := make([]byte, relayChunk) // AEAD 路专用读 buf(伪装路,非热路径目标)。
	batch := make([]byte, 0, relayEncodeBatch+wire.FrameHeaderLen+wire.MaxFrameBodyLen)
	for {
		batch = batch[:0]
		frames := 0
		var readErr error
		for frames < batchFrames {
			rn, err := local.Read(buf)
			if rn > 0 {
				if _, e := tx.EncryptFrameInto(wire.FrameTCPData, buf[:rn], &batch); e != nil {
					return e
				}
				frames++
			}
			if err != nil {
				readErr = err
				break
			}
			if rn < relayChunk {
				break // 短读 → flush(交互流量低延迟)。
			}
		}
		if len(batch) > 0 {
			if _, we := conn.Write(batch); we != nil {
				return we
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				// EOF → TcpClose(空 payload)通知对端流结束。
				batch = batch[:0]
				if _, e := tx.EncryptFrameInto(wire.FrameTCPClose, nil, &batch); e != nil {
					return e
				}
				if _, we := conn.Write(batch); we != nil {
					return we
				}
				return io.EOF
			}
			return readErr
		}
	}
}

// pumpDecode 读 conn 帧 → 解密 → 写 local(解密向;对照 Rust pump_decode)。按快路/伪装路分发:
// 快路([pumpDecodeFast])writev 批量(net.Buffers);伪装路([pumpDecodeAead])per-frame Write。
func pumpDecode(rx *SessionRx, conn io.Reader, local io.Writer) error {
	if rx.NoInnerAEAD() {
		return pumpDecodeFast(rx, conn, local)
	}
	return pumpDecodeAead(rx, conn, local)
}

// frameRange decode 快路本批一帧 body 在 ct buffer 的 (start,end) 偏移(plain int,不持借;对照 Rust ranges)。
type frameRange struct{ start, end int }

// pumpDecodeFast 快路解码批量(writev 零拷贝,对照 Rust pump_decode_fast,relay.rs:194-286)。大 ct buffer 攒
// ≤ batchFrames 帧,多帧 body 一次 net.Buffers.WriteTo(local) = writev(减 server 写 sink 的 write syscall 密度,
// ③(b));快路 body 原位(DecryptFrame 零拷贝返 body 切片)。
//
// 借检两阶段(对照 Rust relay.rs:189-191 注):读/解密阶段记 body 的 (start,end) 偏移(plain int,不持 ct 借);
// writev 阶段从偏移一次性建 net.Buffers(各切片借 ct 不可变区,此阶段不再写 ct)。
//
// 延迟启发式(模块头):满批 OR 小帧(blen < relayChunk,交互/突发尾)立即 writev;bulk 满帧攒批。
func pumpDecodeFast(rx *SessionRx, conn io.Reader, local io.Writer) error {
	// ct 攒帧 buffer:容 batchFrames 帧(每帧 ≤ HEADER+MAX_FRAME_BODY_LEN)。一次性 init → 全区可写,循环复用(0 alloc)。
	capBytes := batchFrames * (wire.FrameHeaderLen + wire.MaxFrameBodyLen)
	ct := make([]byte, capBytes)
	var outDummy []byte // 快路 DecryptFrame 不写 out(零拷贝),签名要 *[]byte;预置空即可。
	ranges := make([]frameRange, 0, batchFrames)

	for {
		ranges = ranges[:0]
		n := 0 // ct 本批已攒字节数。
		// 攒批:读到 batchFrames 帧 / ct 余量不足下一帧 / 小帧(交互)/ EOF / TcpClose / Error。
		// **Go 易踩坑(Rust→Go 移植):`break` 在 switch 内只退 switch 不退 for**(Rust match 内 break 退循环)。
		// 小帧 flush 须退本 for 循环 → 用标签 readBatch(Rust ③ 原 break 的 Go 正确等价)。
	readBatch:
		for len(ranges) < batchFrames {
			// 余量检查:容不下下一帧头 + 最大 body → break 先 writev 本批(ct 满),下轮顶续读。
			if n+wire.FrameHeaderLen+wire.MaxFrameBodyLen > capBytes {
				break
			}
			// 读首字节区分干净 EOF(0 字节)与中段截断(≥1 字节但 <7)。io.ReadFull([1]byte):0 → io.EOF / 1 → nil。
			if _, err := io.ReadFull(conn, ct[n:n+1]); err != nil {
				if errors.Is(err, io.EOF) {
					if len(ranges) == 0 {
						// 批边界干净 EOF:对端正常关(对照 Rust pump_decode_fast 批边界 EOF → Ok + shutdown)。
						return io.EOF
					}
					// 批中段 EOF:本批已攒 → break 先 writev,下轮顶 ranges 空 → 干净 EOF 退(不丢已解密数据)。
					break
				}
				return err // 其他读错(io.ErrUnexpectedEOF 对单字节不可能;真错透出)。
			}
			// 已读 1 字节,补齐剩余帧头;此处 EOF = 帧中段截断 → 错(对照 Rust read_exact)。
			if _, err := io.ReadFull(conn, ct[n+1:n+wire.FrameHeaderLen]); err != nil {
				return err
			}
			hdr, perr := wire.ParseHeader(ct[n : n+wire.FrameHeaderLen])
			if perr != nil {
				return fmt.Errorf("client/relay: %w: %v", ErrInvalidFrameHeader, perr)
			}
			blen := int(hdr.Len)
			bodyStart := n + wire.FrameHeaderLen
			// 钉 slice-安全不变量(对照 Rust debug_assert):余量 check 已保证 n+7+blen ≤ capBytes;fail-loud 兜底。
			if bodyStart+blen > capBytes {
				return fmt.Errorf("client/relay: %w: body_len %d at off %d", ErrFrameTruncated, blen, n)
			}
			if _, err := io.ReadFull(conn, ct[bodyStart:bodyStart+blen]); err != nil {
				return err
			}
			// 快路 decrypt:payload 零拷贝指向 ct[bodyStart:bodyStart+blen](不碰 outDummy)。
			ftype, payload, derr := rx.DecryptFrame(hdr, ct[bodyStart:bodyStart+blen], &outDummy)
			if derr != nil {
				return derr
			}
			n = bodyStart + blen
			switch ftype {
			case wire.FrameTCPData:
				if blen > 0 {
					// 记 body 偏移(plain int,不持 ct 借)→ writev 阶段建 net.Buffers 安全(不与下帧写 ct 冲突)。
					ranges = append(ranges, frameRange{bodyStart, bodyStart + blen})
				}
				// 小帧(交互 / 突发尾)→ 攒完这帧就 writev,不滞留(模块头延迟启发式)。
				// break readBatch(非裸 break):裸 break 只退 switch 不退 for → 小帧永不 flush 死锁(已修)。
				if blen < relayChunk {
					break readBatch
				}
			case wire.FrameTCPClose:
				// 先 writev 已攒的本批 body 再关流(不丢已解密数据)。
				if e := flushRanges(local, ct, ranges); e != nil {
					return e
				}
				return io.EOF // 对端关流 → 半关级联(协调器关 local 解阻塞编码向)。
			case wire.FrameError:
				// 对端 Error 帧(如服务端 dial 目标失败):透出 payload 文本(对照 Rust Error::Peer,MED-1)。
				if e := flushRanges(local, ct, ranges); e != nil {
					return e
				}
				return fmt.Errorf("%w: %s", ErrPeer, string(payload))
			case wire.FramePadding:
				// ADR-016:Padding 塑形帧 —— 无条件消费(盲丢 payload)。不入 ranges(不进 writev)、不 break,
				// 续读同批下帧;ctr 已由 DecryptFrame 推进,此处零额外动作。
				// decode 不门控 caps:Padding 语义即「可丢」,永远非错(反 Ping/Pong/MuxOpen 仍走 default fail-loud)。
				// Go 语义:switch 内裸 `continue` 指 enclosing `for readBatch`(非退 switch)→ 正确续读下帧。
				continue
			default:
				// Ping/Pong/MuxOpen 等出现在数据泵 = 协议违规,fail-loud(对照 Rust Error::Wire)。
				return fmt.Errorf("%w: 0x%02x", ErrUnexpectedFrame, byte(ftype))
			}
		}
		// 本批(满批 / 小帧触发 / 中段 EOF)→ writev。
		if len(ranges) > 0 {
			if e := flushRanges(local, ct, ranges); e != nil {
				return e
			}
		}
	}
}

// pumpDecodeAead 伪装路解码:per-frame Write(对照 Rust pump_decode_aead,relay.rs:291-355)。body 须 AEADDecrypt
// 进复用 out(跨帧攒 net.Buffers 会别名同一 out → 不批量)。body buffer 经 [ReadFrameInto] 复用(0 per-frame alloc)。
func pumpDecodeAead(rx *SessionRx, conn io.Reader, local io.Writer) error {
	var bodyBuf []byte // 复用 body buffer(对照 Rust frame_buf,per-pump 一次 alloc 复用)。
	var out []byte     // AEAD 明文复用(对照 Rust out_buf)。
	for {
		hdr, body, err := ReadFrameInto(conn, &bodyBuf)
		if err != nil {
			// ReadFrameInto:io.EOF = 干净关闭(首字节即 EOF);io.ErrUnexpectedEOF = 帧中段截断(错)。
			return err
		}
		ftype, payload, err := rx.DecryptFrame(hdr, body, &out)
		if err != nil {
			return err
		}
		switch ftype {
		case wire.FrameTCPData:
			if len(payload) > 0 {
				if _, we := local.Write(payload); we != nil {
					return we
				}
			}
		case wire.FrameTCPClose:
			return io.EOF // 对端关流 → 半关级联(协调器关 local 解阻塞编码向)。
		case wire.FrameError:
			// 对端 Error 帧:透出 payload 文本(对照 Rust Error::Peer,MED-1)。
			return fmt.Errorf("%w: %s", ErrPeer, string(payload))
		case wire.FramePadding:
			// ADR-016:Padding 塑形帧 —— 无条件消费(盲丢 payload)。不 Write、不 return,续读下帧。
			// decode 不门控 caps(语义即「可丢」);raw-tcp AEAD 是 dev/test 路,对端若 pad 须对称消费防 Wire error。
			continue
		default:
			// Ping/Pong/MuxOpen 等出现在数据泵 = 协议违规,fail-loud(对照 Rust Error::Wire)。
			return fmt.Errorf("%w: 0x%02x", ErrUnexpectedFrame, byte(ftype))
		}
	}
}

// flushRanges 从 ranges(ct 内 body 偏移)建 net.Buffers 一次 WriteTo(local)(writev;对照 Rust flush_ranges +
// write_vectored_all,relay.rs:360-408)。local 是 *net.TCPConn/*net.UnixConn → net.Buffers.WriteTo 走 writev
// (单 syscall 合并多 body);否则顺序 Write 兜底(正确性不变,丢 syscall 合并增益)。栈数组零 heap alloc(对照
// Rust [IoSlice; BATCH_FRAMES]);ranges ≤ batchFrames → append 不重 alloc。
func flushRanges(local io.Writer, ct []byte, ranges []frameRange) error {
	if len(ranges) == 0 {
		return nil
	}
	var bufsArr [batchFrames][]byte
	bufs := bufsArr[:0]
	for _, r := range ranges {
		bufs = append(bufs, ct[r.start:r.end])
	}
	nb := net.Buffers(bufs)
	if _, err := nb.WriteTo(local); err != nil {
		return err
	}
	return nil
}
