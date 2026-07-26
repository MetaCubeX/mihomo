// fast.go —— 快路握手(transport-provided exporter,0-RTT)。
// 对照 Rust handshake.rs:200-267(fast_client + fast_server),帧字节布局逐位一致(全大端)。
//
// 帧布局:
//
//	FastHello (40B): ver_min:u8 ver_max:u8 caps_c:u16 max_bw_c:u32 auth_tag:32
//
// 无 ServerHello。auth_tag 绑客户端声明值(快路无回告):
//
//	auth_tag = BLAKE3-MAC(k_auth, "speedcat-v1 fast-auth" ‖ exporter ‖ ver ‖ caps_c:BE ‖ max_bw_c:BE)
//
// 其中 k_auth = DeriveKey("speedcat-v1 auth key", psk)。密钥从 exporter 派生。
// NO_INNER_AEAD force **置位**(内层 AEAD 交 TLS record,splice 零拷贝成立)。

package handshake

import (
	"encoding/binary"
	"io"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// fastClient 客户端快路握手(对照 Rust fast_client,handshake.rs:200-228)。
//
// 算 auth_tag → 发 FastHello(40B,搭 auth_tag 0-RTT)→ 从 exporter 派生密钥 → Session。
// conn 取 io.Writer(快路 client 只发 FastHello,不读;握手后由 transport TLS record 承载)。
// exporter 取自 transport.Conn.Exporter()(两端 TLS 1.3 + EMS 字节一致)。
func fastClient(conn io.Writer, psk crypto.Psk, params Params, exporter [crypto.KeyLen]byte) (*Session, error) {
	kAuth := crypto.FastAuthKey(psk)
	authTag := crypto.FastAuthTag(kAuth, crypto.Key(exporter), crypto.VersionMin, crypto.VersionMax, uint16(params.Caps), params.MaxBandwidth)

	// FastHello(方案 1B,40B):ver_min, ver_max, caps_c, max_bw_c, auth_tag。
	var fh [fhLen]byte
	fh[0] = crypto.VersionMin
	fh[1] = crypto.VersionMax
	capsC := params.Caps.Bytes()
	copy(fh[2:4], capsC[:])
	binary.BigEndian.PutUint32(fh[4:8], params.MaxBandwidth)
	copy(fh[8:40], authTag[:])
	if _, err := conn.Write(fh[:]); err != nil {
		return nil, wrapIO(err)
	}

	// 密钥从 exporter 派生(快路 IKM = exporter)。
	keys := crypto.DeriveSessionKeys(crypto.Key(exporter), crypto.WholeConnection)

	// 快路 ⇒ 内层 AEAD 由 TLS record 承担,force 置 NO_INNER_AEAD 位(架构不变量)。
	// 0-RTT:client 不知 server caps/max_bw 策略,记自身声明(乐观);server 按交集 honor(见 FastServer)。
	caps := params.Caps
	caps.SetNoInnerAEAD(true)
	return &Session{Keys: keys, Caps: caps, MaxBandwidth: params.MaxBandwidth}, nil
}

// FastServer 服务端快路握手(对照 Rust fast_server,handshake.rs:230-267)。
//
// 测试 + L4 参考用。读 FastHello → ct_eq 验 auth_tag → 从 exporter 派生密钥 → 按交集 honor → Session。
// **决定性鉴权**:crypto.CTEq 常量时间比对 auth_tag —— PSK 错则 AuthTagMismatch(跨实现铁证,Rust
// fast_server 验失败即拆连 → Go client 见 EOF,e2e 反推窗口)。conn 取 io.Reader(快路 server 只读 FastHello)。
func FastServer(conn io.Reader, psk crypto.Psk, params Params, exporter [crypto.KeyLen]byte) (*Session, error) {
	var fh [fhLen]byte
	if _, err := io.ReadFull(conn, fh[:]); err != nil {
		return nil, wrapIO(err)
	}
	// 方案 1B:客户端版本范围 → 交集选 v*(空则 ErrVersionUnsupported → 上层 fallback,不秒断)。
	// 快路无 ServerHello,v* 无法回告 client(0-RTT 固有限制);仅用于服务端策略,不进 tag(tag 绑范围)。
	verMin := fh[0]
	verMax := fh[1]
	if _, err := negotiateVersion(verMin, verMax); err != nil {
		return nil, err
	}
	capsC := wire.FromBytes([2]byte{fh[2], fh[3]})
	maxBwC := binary.BigEndian.Uint32(fh[4:8])
	var tag [crypto.MacLen]byte
	copy(tag[:], fh[8:40])

	// 常量时间验 auth_tag(对照 Rust crypto::ct_eq)。tag 绑 ver_min/ver_max/caps_c/max_bw_c(客户端声明),用收到的值重算比对。
	kAuth := crypto.FastAuthKey(psk)
	expect := crypto.FastAuthTag(kAuth, crypto.Key(exporter), verMin, verMax, uint16(capsC), maxBwC)
	if !crypto.CTEq(tag[:], expect[:]) {
		return nil, ErrAuthTagMismatch
	}

	// auth_tag 已绑 caps_c / max_bw_c(客户端无法事后篡改)。server 在此执行策略(HIGH-A 闭合):
	// (1) caps 取与本端 params 的交集——客户端声明了本端不支持的位会被丢弃;
	// (2) max_bw clamp 到本端策略上限;
	// (3) force NO_INNER_AEAD 位(快路架构不变量),与 crypto flag 一致 → 闭合 HIGH-B 两套真相。
	// 0-RTT 无 ServerHello:协商结果无法回告 client(与 auth_tag 同限制);server 只按此交集 honor。
	caps := wire.Negotiate(capsC, params.Caps)
	caps.SetNoInnerAEAD(true)
	maxBw := clampMaxBW(maxBwC, params.MaxBandwidth)
	keys := crypto.DeriveSessionKeys(crypto.Key(exporter), crypto.WholeConnection)
	return &Session{Keys: keys, Caps: caps, MaxBandwidth: maxBw}, nil
}
