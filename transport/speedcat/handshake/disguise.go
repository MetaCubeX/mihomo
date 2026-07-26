// disguise.go —— 伪装路握手(eph DH ClientHello/ServerHello,+1 RTT)。
// 对照 Rust handshake.rs:73-190(disguise_client + disguise_server),帧字节布局逐位一致(全大端)。
//
// 帧布局:
//
//	ClientHello (56B): ver_min:u8 ver_max:u8 caps_c:u16 eph_c:32 nonce_c:16 max_bw_c:u32
//	ServerHello (55B): ver:u8 caps_s:u16 eph_s:32 nonce_s:16 max_bw_s:u32
//
// 密钥流:DH shared → blake3_mac(psk, hs_input) → handshake_secret → DeriveSessionKeys。
// NO_INNER_AEAD force **清位**(伪装路自带双层 AEAD)。**握手恒完成**(无显式 auth)。

package handshake

import (
	"encoding/binary"
	"io"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// disguiseClient 客户端伪装路握手(对照 Rust disguise_client,handshake.rs:73-131)。
//
// [1] 发 ClientHello(56B) → [2] 读 ServerHello(55B) → DH + 派生 → Session。
// conn 取 io.ReadWriter(transport.Conn 满足;net.Pipe 亦满足 —— self-test 用)。
func disguiseClient(conn io.ReadWriter, psk crypto.Psk, params Params) (*Session, error) {
	kp, err := crypto.NewDhKeypair()
	if err != nil {
		return nil, err
	}
	nonceC, err := crypto.RandomHSNonce()
	if err != nil {
		return nil, err
	}
	verMin, verMax := crypto.VersionMin, crypto.VersionMax

	// [1] ClientHello(56B,方案 1B:携本端支持版本范围 [ver_min, ver_max])。
	var ch [chLen]byte
	ch[0] = verMin
	ch[1] = verMax
	capsC := params.Caps.Bytes()
	copy(ch[2:4], capsC[:])
	pubC := kp.PublicBytes()
	copy(ch[4:36], pubC[:])
	copy(ch[36:52], nonceC[:])
	binary.BigEndian.PutUint32(ch[52:56], params.MaxBandwidth)
	if _, err := conn.Write(ch[:]); err != nil {
		return nil, wrapIO(err)
	}

	// [2] ServerHello(55B)。
	var sh [shLen]byte
	if _, err := io.ReadFull(conn, sh[:]); err != nil {
		return nil, wrapIO(err)
	}
	// 方案 1B:ServerHello.ver = 服务端选中 v*,须落在本端声明范围内(否则坏 server / 中间人);ver_sel 进 MAC 抗下行降级。
	verSel := sh[0]
	if verSel < verMin || verSel > verMax {
		return nil, ErrVersionUnsupported
	}
	capsS := wire.FromBytes([2]byte{sh[1], sh[2]})
	var ephS [crypto.KeyLen]byte
	copy(ephS[:], sh[3:35])
	var nonceS [crypto.HsNonceLen]byte
	copy(nonceS[:], sh[35:51])
	maxBwS := binary.BigEndian.Uint32(sh[51:55])

	// DH + 密钥派生。
	shared, err := kp.DH(ephS)
	if err != nil {
		return nil, err // crypto.ErrDhNonContributory(全零/低序点拒, line 91)
	}
	capsNeg := wire.Negotiate(params.Caps, capsS)
	input := crypto.DisguiseHSInput(verMin, verMax, verSel, shared, nonceC, nonceS, uint16(capsNeg), params.MaxBandwidth, maxBwS)
	hsSecret := crypto.Blake3Mac(crypto.Key(psk), input)
	keys := crypto.DeriveSessionKeys(crypto.Key(hsSecret), crypto.WholeConnection)

	// 伪装路 = 双层 AEAD,force 清 NO_INNER_AEAD 位;client max_bw 用自身声明(对照 Rust handshake.rs:124-130)。
	caps := capsNeg
	caps.SetNoInnerAEAD(false)
	return &Session{Keys: keys, Caps: caps, MaxBandwidth: params.MaxBandwidth}, nil
}

// DisguiseServer 服务端伪装路握手(对照 Rust disguise_server,handshake.rs:133-190)。
//
// 测试 + L4 参考用(本轮 Go client 侧主产;此 fn 是 Rust server 侧的 Go 镜像,供 Go↔Go self-test
// 跑两端握手比对密钥)。读 ClientHello → DH + 派生 → 发 ServerHello → Session。
//
// **恒完成、无显式 auth**:不校验 PSK(密钥确认隐式于首帧 AEAD);故握手成功 ≠ PSK 对(见包 doc)。
func DisguiseServer(conn io.ReadWriter, psk crypto.Psk, params Params) (*Session, error) {
	// [1] ClientHello(56B)。
	var ch [chLen]byte
	if _, err := io.ReadFull(conn, ch[:]); err != nil {
		return nil, wrapIO(err)
	}
	// 方案 1B:客户端声明版本范围 → 与本端交集选 v*(空则 VersionUnsupported → 上层 fallback,不秒断)。
	verMin, verMax := ch[0], ch[1]
	verSel, err := negotiateVersion(verMin, verMax)
	if err != nil {
		return nil, err
	}
	capsC := wire.FromBytes([2]byte{ch[2], ch[3]})
	var ephC [crypto.KeyLen]byte
	copy(ephC[:], ch[4:36])
	var nonceC [crypto.HsNonceLen]byte
	copy(nonceC[:], ch[36:52])
	maxBwC := binary.BigEndian.Uint32(ch[52:56])

	// 生成 server eph + nonce(Go 值语义:PublicBytes 先取后 DH 都安全,无 Rust move 顾虑)。
	kp, err := crypto.NewDhKeypair()
	if err != nil {
		return nil, err
	}
	pubS := kp.PublicBytes()
	nonceS, err := crypto.RandomHSNonce()
	if err != nil {
		return nil, err
	}
	capsNeg := wire.Negotiate(capsC, params.Caps)

	shared, err := kp.DH(ephC)
	if err != nil {
		return nil, err
	}
	input := crypto.DisguiseHSInput(verMin, verMax, verSel, shared, nonceC, nonceS, uint16(capsNeg), maxBwC, params.MaxBandwidth)
	hsSecret := crypto.Blake3Mac(crypto.Key(psk), input)
	keys := crypto.DeriveSessionKeys(crypto.Key(hsSecret), crypto.WholeConnection)

	// [2] ServerHello(55B):声明本端 caps(params.Caps,非协商值)+ eph_s + nonce_s + max_bw_s。
	var sh [shLen]byte
	sh[0] = verSel // 方案 1B:回告选中的 v*(客户端验其落在自身范围 + 进 MAC)
	capsS := params.Caps.Bytes()
	copy(sh[1:3], capsS[:])
	copy(sh[3:35], pubS[:])
	copy(sh[35:51], nonceS[:])
	binary.BigEndian.PutUint32(sh[51:55], params.MaxBandwidth)
	if _, err := conn.Write(sh[:]); err != nil {
		return nil, wrapIO(err)
	}

	// 伪装路 force 清 NO_INNER_AEAD 位;server max_bw clamp 客户端声明到本端策略上限(HIGH-A)。
	caps := capsNeg
	caps.SetNoInnerAEAD(false)
	return &Session{Keys: keys, Caps: caps, MaxBandwidth: clampMaxBW(maxBwC, params.MaxBandwidth)}, nil
}
