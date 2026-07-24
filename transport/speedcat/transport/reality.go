// reality.go —— Reality 伪装路 TCP dial arm(C7b / C7c 复议;对照 Rust proto-tls/src/reality.rs RealityConn +
// reference/Xray-core/transport/internet/reality/reality.go 客户端注入模板 + mihomo-fork/component/tls/reality.go)。
//
// **无 TLS exporter** —— Exporter()/ExporterWithLabel() 均返 [ErrRealityNoExporter](同 rawtcp.go)。
// handshake.Client 拿到 exporter 探针失败 → 路由 disguiseClient(eph DH ClientHello/ServerHello + 双层
// AEAD,NO_INNER_AEAD force OFF)→ 接管后内层 disguise 协议跑在 Reality TLS 隧道里(两端伪装路跨实现:
// Go reality dial ↔ Rust reality 接管 + disguise_server)。
//
// # 两层 auth 分域(D2,docs/05 §3.3)
//
// 外层 REALITY auth(本文件)= 门卫:决定 Rust 服务端接管(发 ECDSA-P256 自签 forge cert)vs 转发 dest
// (无凭据探测者)。AuthKey(C1 HKDF)**不进** speedcat 会话密钥派生也不进 TLS 流量密钥派生,亦**不进**
// cert 层身份证明(C7c 复议,见下)。会话密钥由内层 disguise 协议产;RealityConn exporter 返 Err →
// 强制 disguise(两层独立)。
//
// # C7c 命门修正(cert 算法 ed25519 → ECDSA-P256;ADR-012 复议)
//
// ADR-012 首版用 ed25519 forge cert + 签名域藏 HMAC-SHA512。跨实现 e2e(Go utls Chrome 指纹 client ↔
// Rust rustls server)实测 rustls 报 NoSignatureSchemesInCommon —— Chrome 的 signature_algorithms 不含
// ed25519(0x0807),rustls **严格** server 无法为 ed25519 cert 选 CertificateVerify 方案 → 握手断。
// mihomo REALITY 能用 ed25519 是因其 server = Go crypto/tls(**宽松**:无视 client 宣告表);speedcat
// server = rustls(RFC 严格)。修正:cert 改 **ECDSA-P256 自签**(Chrome 宣告,合法自签,无 HMAC 覆盖)
// → cert 层降为「接管/转发区分器」(self-signed = 接管;CA-signed dest cert = 转发),**真实服务端身份
// 下沉到内层 disguise PSK 互认证**(speedcat 有 REALITY 缺失的内层 auth,故 cert 层不需密码学身份证明)。
//
// # 注入流程(对齐 REALITY 生态 + C3-fix AAD 契约)
//
//  1. utls.UClient(Chrome 指纹;InsecureSkipVerify=true + 自定义 VerifyPeerCertificate)
//  2. BuildHandshakeState() → hello(utls 自产 random/keyShare[X25519])
//  3. 清零 hello.Raw[39:71](sessionId 段)→ 此刻 hello.Raw = AAD(message,C3-fix:剥 record header 的
//     message == Rust aad_with_session_id_zeroed,逐字节一致)
//  4. ecdhe = State13.KeyShareKeys.Ecdhe(utls 自产 X25519 临时对;eph_pub 已在 key_share 扩展里,服务端
//     parse 出来作 DH peer_pub —— 故**不另注入 keyShare**,用 utls 自带的,两端 DH 对称)
//  5. sessionCT, _ = crypto.ClientEncode(serverPub, ecdhe 标量, hello.Random, payload, AAD)
//     (DH + HKDF + AES-GCM seal → 32B 密文;authKey 返回值 C7c 后弃用,身份下沉内层 disguise)
//  6. hello.SessionId = sessionCT;copy(hello.Raw[39:], sessionCT) —— 写回 Raw(utls 用 mutated Raw 发 CH)
//  7. HandshakeContext() → Rust 服务端 peek CH → decode → 接管(forge cert ECDSA-P256 自签)
//  8. VerifyPeerCertificate(cert chain[0]):cert.CheckSignature(自签校验,ECDSA-P256)过 → verified=true;
//     否则若 cert 是 dest 真证书(被转发)x509.Verify 过 → verified 留 false(握手完,后判)。
//  9. verified=false → fallback HTTP(貌似浏览器收尾)+ ErrRealityAuthFailed(非裸拒)。
//
// # fail-safe
//
// InsecureSkipVerify=true **但不裸放行**:VerifyPeerCertificate 校 cert 自签(C7c:ECDSA-P256
// CheckSignature)+ dest 真 cert x509.Verify(非 CA 链;REALITY 自签临时 cert 无 CA)。无 serverPriv →
// Rust 服务端 decode 失败 → 转发 dest(dest 真 cert 自签校验不过 → verified=false)。
// **真实身份由内层 disguise PSK 互认证担**(两层 auth 分域 D2;MITM 即使伪造自签 cert 过 cert 层,内层
// disguise 握手被 PSK 拒)。**panic-free**(被 mihomo import 的库:dial/握手错返 error)。
//
// **§5.4:** 不打 PSK/AuthKey/ClientHello 原文/ sessionId 密文明文(只返 error + 收尾)。

package transport

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	utls "github.com/metacubex/utls"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
)

// ErrRealityNoExporter Reality TLS exporter 故意不可用(同 rawtcp;handshake.Client 据此路由 disguiseClient)。
// 对照 Rust RealityConn::export_keying_material 返 None(两层 auth 分域 D2)。
var ErrRealityNoExporter = errors.New("transport/reality: 无 TLS exporter(伪装路两层 auth:外层 REALITY 门卫 + 内层 disguise)")

// ErrRealityAuthFailed 服务端 cert 非 speedcat 自签 forge cert(被转发 dest / MITM / 配置错)。
var ErrRealityAuthFailed = errors.New("transport/reality: 服务端非接管(forge cert 非自签 / 被转发 dest)")

// RealityFingerprint 默认 utls 指纹(Chrome_Auto = 最常见浏览器 → 最佳被动伪装;对照 mihomo ClientFingerprint)。
var RealityFingerprint = utls.HelloChrome_Auto

// realityFallbackUA 失败收尾 HTTP 请求的 UA(貌似 Chrome 浏览器;让 dest 观察者看到正常访问)。
const realityFallbackUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// stripMLKEM768KeyShares 从 SupportedCurves + KeyShare 两扩展里删 X25519MLKEM768(PQ)项。
// 对照 mihomo component/tls/utls.go BuildRemovedX25519MLKEM768HandshakeState 的 strip 段(非 PQ 服务端默认)。
// 须在 BuildHandshakeState 后调(填充了 uConn.Extensions);strip 后须再 BuildHandshakeState 重算 Raw。
//
// 为何剥:Rust C1 服务端 parse_key_share_x25519 只认 group=0x001d(plain X25519,32B),不处理 PQ。
// 现代 Chrome_Auto 指纹含 PQ keyshare;不剥 → 服务端找不到 0x001d → decode 失败 → 转发 dest(握手白做)。
// 剥后仅剩 plain X25519 → KeyShareKeys.Ecdhe 必非 nil,两端 DH 对称成立。
func stripMLKEM768KeyShares(u *utls.UConn) {
	for _, ext := range u.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			e.Curves = slices.DeleteFunc(e.Curves, func(c utls.CurveID) bool { return c == utls.X25519MLKEM768 })
		case *utls.KeyShareExtension:
			e.KeyShares = slices.DeleteFunc(e.KeyShares, func(s utls.KeyShare) bool { return s.Group == utls.X25519MLKEM768 })
		}
	}
}

// dialReality 建立 Reality 伪装路连接:utls Chrome 指纹 + auth 注入 ClientHello → 接管握手。
// 返回 [RealityConn](exporter 返 ErrRealityNoExporter,强制内层 disguise)。对照 Rust proto-tls/src/reality.rs。
func dialReality(ctx context.Context, cfg Config) (Conn, error) {
	if cfg.RealityPubKey == ([crypto.KeyLen]byte{}) {
		// fail-loud:无 server 静态公钥无法算 AuthKey(无法注入 auth)。
		return nil, errors.New("transport/reality: RealityPubKey 未配(server X25519 静态公钥,base64url)")
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/reality: tcp dial %s: %w", addr, err)
	}

	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Host // Rust config.rs:720:SNI 缺省 = host
	}
	verifier := &realityVerifier{serverName: sni}
	uConn := utls.UClient(raw, &utls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     true, // 不裸放行:VerifyPeerCertificate 校 cert 自签 + dest 真 cert(非 CA 链)
		SessionTicketsDisabled: true, // 无 PSK binder,reality 注入后无须重算 binder(对齐 REALITY)
		VerifyPeerCertificate:  verifier.VerifyPeerCertificate,
	}, RealityFingerprint)
	verifier.uConn = uConn // verifier 取 PeerCertificates 时用(本实现走 rawCerts 回调,留作诊断钩子)

	// 首 build:应用指纹变量 + 填充 uConn.Extensions(才能 strip)+ 算出 random/keyShare。
	if err := uConn.BuildHandshakeState(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("transport/reality: BuildHandshakeState: %w", err)
	}

	// **剥 X25519MLKEM768(PQ keyshare)** —— 现代 Chrome_Auto 指纹含 PQ keyshare;Rust C1 服务端
	// parse_key_share_x25519 只认 group=0x001d(plain X25519,32B)。剥掉 PQ → 仅剩 plain X25519
	// keyshare → KeyShareKeys.Ecdhe 必非 nil,服务端必能解出 eph_pub(对照 mihomo
	// component/tls/utls.go BuildRemovedX25519MLKEM768HandshakeState,非 PQ 服务端默认行为)。
	stripMLKEM768KeyShares(uConn)
	// 重建:按剥后的 spec 重算 hello.Raw(否则 strip 未落 Raw,服务端仍读到 PQ keyshare)。
	if err := uConn.BuildHandshakeState(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("transport/reality: rebuild after strip: %w", err)
	}

	hello := uConn.HandshakeState.Hello
	if len(hello.SessionId) != crypto.SessionCTLen || len(hello.Raw) < 39+crypto.SessionCTLen {
		_ = raw.Close()
		return nil, fmt.Errorf("transport/reality: hello 布局异常(SessionId %dB / Raw %dB)",
			len(hello.SessionId), len(hello.Raw))
	}

	// ① 清零 hello.Raw[39:71](sessionId 段,message-relative 偏移 39;C3-fix AAD 契约)→ AAD。
	//    此刻 hello.Raw = 「sessionId 清零版 ClientHello message」== Rust aad_with_session_id_zeroed(剥 5B record header)。
	for i := range hello.Raw[39 : 39+crypto.SessionCTLen] {
		hello.Raw[39+i] = 0
	}

	// ② utls 自产 X25519 临时对(State13.KeyShareKeys.Ecdhe):eph_pub 已在 key_share 扩展里,服务端 parse
	//    出来作 DH peer_pub —— 故不另注入 keyShare,用 utls 自带的(两端 DH 对称,eph 公钥一致)。
	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		_ = raw.Close()
		return nil, errors.New("transport/reality: utls 指纹无 X25519 keyShare(须 TLS1.3 指纹)")
	}
	var ephPriv [crypto.KeyLen]byte
	copy(ephPriv[:], ecdhe.Bytes()) // X25519 私钥标量(32B);ClientEncode 内部 curve25519.X25519(ephPriv, serverPub)

	// ③ ClientEncode:DH(ephPriv, serverPub)+ HKDF + AES-GCM seal(AAD = sessionId 清零版 hello.Raw)
	//    → sessionCT(32B)。nonce/salt 取自 hello.Random(random[20:32]/random[:20])。
	//    返回的 authKey(C7c 复议后)不进 cert —— 身份下沉内层 disguise,此处丢弃。
	var random [crypto.RandomLen]byte
	copy(random[:], hello.Random)
	payload := crypto.AuthPayload{
		Version: crypto.ProtocolVersion,
		Time:    uint32(time.Now().Unix()),
		ShortID: cfg.RealityShortID,
	}
	sessionCT, _, err := crypto.ClientEncode(cfg.RealityPubKey, ephPriv, random, payload, hello.Raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("transport/reality: ClientEncode(DH+HKDF+seal): %w", err)
	}

	// ④ 把密文写回 hello.SessionId + hello.Raw[39:](utls 用 mutated Raw 发 ClientHello;无 PSK binder 须重算)。
	copy(hello.SessionId[:], sessionCT[:])
	copy(hello.Raw[39:], sessionCT[:])

	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("transport/reality: handshake: %w", err)
	}
	if !verifier.verified {
		// 非 bare 拒:先貌似浏览器对 dest 收尾(REALITY 先例:让观察者看到正常访问而非「鉴权失败即断」),
		// 再返 auth 失败。spawn 不阻塞(收尾 conn 生命周期独立;caller 已拿不到 conn)。
		go realityClientFallback(uConn, sni)
		return nil, ErrRealityAuthFailed
	}
	return &RealityConn{c: uConn}, nil
}

// RealityConn 包 *utls.UConn(接管握手后):字节流(io.ReadWriteCloser)+ exporter 探针恒失败(伪装路命门,
// 强制内层 disguiseClient)。对照 Rust RealityConn(exporter None;两层 auth 分域 D2)。
type RealityConn struct{ c *utls.UConn }

func (r *RealityConn) Read(p []byte) (int, error)  { return r.c.Read(p) }
func (r *RealityConn) Write(p []byte) (int, error) { return r.c.Write(p) }
func (r *RealityConn) Close() error                { return r.c.Close() }

// Exporter Reality 故意无 exporter(强制 disguiseClient)。对照 Rust RealityConn::export_keying_material None。
func (r *RealityConn) Exporter() ([crypto.KeyLen]byte, error) {
	return [crypto.KeyLen]byte{}, ErrRealityNoExporter
}

// ExporterWithLabel 同 [RealityConn.Exporter](Reality 任何 label 都无 exporter;伪装路不取)。
func (r *RealityConn) ExporterWithLabel(string) ([crypto.KeyLen]byte, error) {
	return [crypto.KeyLen]byte{}, ErrRealityNoExporter
}

// realityVerifier 校验服务端 cert(C7c 复议:ECDSA-P256 自签 forge cert,身份下沉内层 disguise)。
// 对照 Rust RealityServerCertVerifier(accept-any,test-only)+ Xray/mihomo realityVerifier 语义。
//
// 两路径(对齐 REALITY):
//   - 路径 A(speedcat forge cert):ECDSA-P256 合法**自签**(cert.CheckSignature 过)→ verified=true(接管)。
//   - 路径 B(被转发 dest,真 cert):自签校验不过(leaf 公钥签不动自己 TBS)但 cert 经 x509.Verify 过(dest 真
//     cert,如 cloudflare)→ 返 nil(握手完成,verified 留 false),调用方据此判「拿到 dest 而非 speedcat 服务」。
//   - 两路都不过 → 真 MITM/篡改 → 返 err 拒。
//
// **cert 层只作接管/转发区分器**(C7c);真实服务端身份由内层 disguise PSK 互认证担(两层 auth 分域 D2)。
type realityVerifier struct {
	uConn      *utls.UConn
	serverName string
	verified   bool
}

// VerifyPeerCertificate utls 回调(rawCerts = 服务端 cert 链 DER)。InsecureSkipVerify=true 下此回调是唯一校验。
func (v *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("transport/reality: 服务端未发证书")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		// C7c 命门:cert 须合法 DER(ECDSA-P256 自签不破坏 DER);parse 失败 = 非 speedcat/篡改。
		return fmt.Errorf("transport/reality: 解析服务端 cert: %w", err)
	}

	// 路径 A:speedcat forge cert(ECDSA-P256 合法自签;C7c 复议)。cert.CheckSignature 用 cert.PublicKey
	// 验自己 TBS 签名 → 自签校验过 → verified。**用 CheckSignature 非 CheckSignatureFrom**:后者强制
	// IsCA/KeyUsageCertSign,非 CA 自签 forge cert 无。**接管/转发区分器(C7c)**:self-signed(leaf 公钥能
	// 验自己 TBS 签名 → 过)= 接管;CA-signed dest cert(签名由 CA 私钥做,leaf 公钥验不动自己 TBS → 不过)
	// = 转发。真实身份由内层 disguise PSK 互认证担(两层 auth 分域 D2)。
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err == nil {
		v.verified = true
		return nil
	}

	// 路径 B:被转发到 dest(dest 真 CA-signed cert)。x509.Verify(系统 roots + 中间证书)过 → 返 nil,verified 留 false。
	opts := x509.VerifyOptions{
		DNSName:       v.serverName,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
	}
	for _, der := range rawCerts[1:] {
		if ic, e := x509.ParseCertificate(der); e == nil {
			opts.Intermediates.AddCert(ic)
		}
	}
	if _, err := cert.Verify(opts); err != nil {
		// 既非 speedcat 自签 forge cert,也非合法 dest cert → 真 MITM/篡改/未知 → 拒。
		return fmt.Errorf("transport/reality: cert 非 speedcat 自签 forge 亦非合法 dest 证书: %w", err)
	}
	return nil // dest 真 cert(被转发)→ 握手过,verified=false(调用方后判 fallback)
}

// realityClientFallback 失败收尾:对 dest 发一个貌似 Chrome 浏览器的 HTTP/1.1 请求后关连
// (REALITY 先例:让 MITM/dest 观察者看到「浏览器访问站」而非「鉴权失败即断」,消除行为指纹)。
// best-effort,错误忽略(已是失败路径);不阻塞主流程(已 spawn goroutine)。
func realityClientFallback(uConn net.Conn, serverName string) {
	defer uConn.Close()
	req := "GET / HTTP/1.1\r\n" +
		"Host: " + serverName + "\r\n" +
		"User-Agent: " + realityFallbackUA + "\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	_ = uConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = uConn.Write([]byte(req))
	_ = uConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	_, _ = uConn.Read(buf) // best-effort drain dest 响应
}
