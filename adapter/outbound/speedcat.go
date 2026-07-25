// Package outbound · speedcat —— speedcat(速猫)outbound adapter(docs/17 §4 4-switch fork 第 2 件)。
//
// 把 Rust speedcat server 接成 mihomo 原生 outbound 类型。协议实现(线格式 / 握手 / relay /
// UDP 双路径)vendored 在本仓 `transport/speedcat/`(docs/17 §4;原 SSOT = speedcat 仓 adapter/mihomo,
// 此为 vendored 快照 —— 协议库进树后零外部私有依赖,blake3 切 metacubex 对齐 mihomo 依赖栈)。
// 本文件只做 mihomo ProxyAdapter 契约 ↔ speedcat 协议库 的阻抗桥接:
//
//   - TCP(DialContext,C2 填实):mihomo 要 net.Conn;speedcat *StreamConn 只有 Relay(local)桥
//     (非 net.Conn)→ net.Pipe + goroutine StreamConn.Relay(pipeA) 保 L4-B 批量合帧零拷贝,返 pipeB。
//   - UDP(ListenPacketContext,C3 填实):mihomo 要 net.PacketConn;speedcat *UdpTunnel 是 SendTo/RecvFrom
//     (非 net.PacketConn,且签名带 ctx)→ speedcatPacketConn 包之(ReadFrom↔RecvFrom / WriteTo↔SendTo,
//     wire.Addr↔net.Addr;ctx 绑定 conn 生命周期,Close 取消);两臂(QUIC datagram / TCP 流隧道)client
//     按 transport kind 自决 → adapter 统一包。
//
// C1:struct + SpeedcatOption + NewSpeedcat + Dial/ListenPacket stub。C2:DialContext。C3(本提交):
// ListenPacketContext + speedcatPacketConn(net.PacketConn 桥接)+ addr 双向转换。
// 构造照 anytls.go 模板;proxy: tag(非 yaml:)内嵌 BasicOption(白拿 dialer-proxy 等)。
package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/mihomo/transport/speedcat/client"
	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/handshake"
	"github.com/metacubex/mihomo/transport/speedcat/transport"
	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// Speedcat 是 speedcat outbound —— 持协议客户端 + 配置,实现 C.ProxyAdapter。
type Speedcat struct {
	*Base
	client *client.Client // 协议客户端(握手 + relay + UDP;首次 Dial 时才联网,构造仅装配)
	option *SpeedcatOption
}

// SpeedcatOption 是 speedcat outbound 的配置(proxy: tag,内嵌 BasicOption 白拿
// dialer-proxy/tfo/mptcp/interface-name/routing-mark/ip-version)。
// password = PSK(64 hex,speedcat genkey 生成);transport = tcp|quic(快路)|raw-tcp(伪装路,双层 AEAD)。
type SpeedcatOption struct {
	BasicOption
	Name           string `proxy:"name"`
	Server         string `proxy:"server"`
	Port           int    `proxy:"port"`
	Password       string `proxy:"password"`                   // PSK(64 hex)
	SNI            string `proxy:"sni,omitempty"`              // TLS SNI(缺省=server)
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"` // dev 自签证书旁路(fail-safe:默认 false = 校验)
	ALPN           string `proxy:"alpn,omitempty"`             // 单 ALPN(缺省空;QUIC 强制时两端固定 speedcat/1)
	UDP            bool   `proxy:"udp,omitempty"`              // 声明支持 UDP(routing 决策用)
	Transport      string `proxy:"transport,omitempty"`        // tcp|quic|raw-tcp(缺省 tcp)
}

// DialContext 实现 C.ProxyAdapter —— TCP CONNECT 经 speedcat server 代理。
//
// 阻抗桥接(4-switch 第 2 件,C2 填实):mihomo 要 net.Conn;speedcat *StreamConn 只有
// Relay(local)桥方法(非 net.Conn、无 Read/Write)→ net.Pipe 建两端,goroutine 跑
// StreamConn.Relay(pipeA)(Relay 内部两向并发 pump —— 镜像 Rust relay.rs,故 net.Pipe 同步
// 语义下无死锁),返 pipeB 经 NewConn 包给 mihomo。保 L4-B 批量合帧零拷贝(relay 在 goroutine
// 内合帧/writev,pipe 仅搬运)。Relay 返回即一侧 EOF/关 → goroutine 关 pipeA + sc(防泄漏)。
func (s *Speedcat) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	target := metadataToSpeedcatAddr(metadata)
	sc, err := s.client.Dial(ctx, target) // 握手 + TcpConnect(握手延后到首次 Dial,NewSpeedcat 仅装配)
	if err != nil {
		return nil, err
	}

	pipeA, pipeB := net.Pipe()
	go func() {
		_ = sc.Relay(pipeA) // speedcat conn ↔ pipeA 双向桥接(Relay 内已按半关语义局部 Close)
		_ = pipeA.Close()
		_ = sc.Close()
	}()
	return NewConn(pipeB, s), nil
}

// ListenPacketContext 实现 C.ProxyAdapter —— UDP 经 speedcat server 代理(C3 填实,4-switch 第 2 件 UDP 侧)。
//
// 阻抗桥接:mihomo 要 net.PacketConn;speedcat *UdpTunnel 只有 SendTo/RecvFrom(带 ctx,非 net.PacketConn)
// → speedcatPacketConn 包之(ReadFrom↔RecvFrom / WriteTo↔SendTo,ctx 绑 conn 生命周期,Close 取消)。
// client.DialUDP 按 transport kind 自决两臂(QUIC datagram / TCP 流隧道)→ adapter 统一包,调用方零分支。
// NewPacketConn 再叠 EnhancePacketConn(异步 WaitReadFrom)+ DeadlineEnhancePacketConn(goroutine+timer
// 竞争式实现 deadline,不依赖本 conn 的 SetReadDeadline —— 故 SetXxxDeadline no-op 是预期模式)。
func (s *Speedcat) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	target := metadataToSpeedcatAddr(metadata)
	tunnel, err := s.client.DialUDP(ctx, target) // 握手 + UdpAssociate 首帧 + 按 kind 分臂 spawn relay(握手延后)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(newSpeedcatPacketConn(tunnel), s), nil
}

// SupportUDP 声明本 outbound 支持 UDP(routing 决策用;随配置 udp= 透传)。
// 真实 UDP 能力由协商 caps 定(非 yaml flag);client.DialUDP 已按 kind 自决两臂(C3 起实证)。
func (s *Speedcat) SupportUDP() bool {
	return s.option != nil && s.option.UDP
}

// SupportUOT 返回 false —— speedcat 用自家 UDP tunnel(QUIC datagram / TCP 流隧道),
// 非 sing uot(sing/common/uot);不向 UI 报告 UoT 支持。
func (s *Speedcat) SupportUOT() bool {
	return false
}

// ProxyInfo 实现 C.ProxyAdapter —— 透出 dialer-proxy(照 anytls,option.DialerProxy 来自 BasicOption)。
func (s *Speedcat) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

// Close 实现 C.ProxyAdapter —— C2 起关底层 StreamConn/UdpTunnel 池;当前协议库 client 无显式 Close。
func (s *Speedcat) Close() error {
	return nil
}

// NewSpeedcat 构造 speedcat outbound:解 PSK + 解 transport kind + 组 transport.Config +
// 声明 caps(UDP 两路径都支持)+ 装配协议 client(握手延后到首次 Dial)。fail-loud:PSK 非法 /
// transport 未知 → 返 error(照 mihomo 既有 outbound 错误路径,§6.1 Go adapter 返 error 不 panic)。
func NewSpeedcat(option SpeedcatOption) (*Speedcat, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	// fail-loud:64 hex PSK 解析失败(长度错 / 非 hex)直接拒构造,不静默降级。
	psk, err := crypto.ParsePSKHex(option.Password)
	if err != nil {
		return nil, err
	}

	kind, err := parseSpeedcatKind(option.Transport)
	if err != nil {
		return nil, err
	}

	// caps:UDP 两路径都声明(QUIC datagram + TCP 流隧道);NO_INNER_AEAD 由握手按路径 force。
	// 对照 adapter/mihomo/cmd/speedcat-socks5/main.go:62(Rust HandshakeParams::default + UDP caps)。
	caps := wire.CapHasDatagram | wire.CapUDPTunnelOK

	cfg := transport.Config{
		Host:     option.Server,
		Port:     option.Port,
		SNI:      option.SNI,
		ALPN:     option.ALPN,
		Insecure: option.SkipCertVerify,
	}
	cl := client.NewClient(cfg, kind, psk, handshake.Params{Caps: caps})

	return &Speedcat{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Speedcat,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		client: cl,
		option: &option,
	}, nil
}

// parseSpeedcatKind 把配置字符串映射到 transport.Kind(缺省 tcp;对照 sidecar main.go:108 parseTransport
// 单点同款映射)。raw-tcp = 伪装路(裸 TCP 无 exporter → disguiseClient 双层 AEAD)。
func parseSpeedcatKind(s string) (transport.Kind, error) {
	switch s {
	case "", "tcp":
		return transport.KindTCP, nil
	case "quic":
		return transport.KindQUIC, nil
	case "raw-tcp":
		return transport.KindRawTCP, nil
	default:
		return 0, fmt.Errorf("未知 transport %q(支持:tcp | quic | raw-tcp)", s)
	}
}

// metadataToSpeedcatAddr mihomo Metadata → speedcat wire.Addr。atype 映射:domain→0x02 / IPv4→0x01 /
// IPv6→0x03(**与 SOCKS5 atype 不同**,易踩坑 #2,见 adapter/mihomo/client/socks5.go:7-13;speedcat 域名=0x02
// 是 VLESS/v2ray 习惯,docs/02 §5)。优先 domain(让 Rust server 远端解析 DNS);纯 IP 目标按族填 IPv4/IPv6。
func metadataToSpeedcatAddr(metadata *C.Metadata) wire.Addr {
	a := wire.Addr{Port: metadata.DstPort}
	if metadata.Host != "" {
		a.Type = wire.AddrTypeDomain
		a.Domain = metadata.Host
		return a
	}
	if metadata.DstIP.IsValid() {
		// Unmap 规约 4-in-6 → 真 IPv4(Is4 守 As4:非 IPv4 调 As4 会 panic);mihomo 存的 DstIP 通常已 Unmap,保险再调。
		ip := metadata.DstIP.Unmap()
		if ip.Is4() {
			a.Type = wire.AddrTypeIPv4
			a.IPv4 = ip.As4()
		} else {
			a.Type = wire.AddrTypeIPv6
			a.IPv6 = ip.As16()
		}
	}
	return a
}

// speedcatPacketConn 把 speedcat *UdpTunnel(SendTo/RecvFrom,带 ctx)桥接成 net.PacketConn(ReadFrom/WriteTo,
// 无 ctx)供 mihomo NewPacketConn 包。ctx 绑定 conn 生命周期:Close 取消 → RecvFrom/SendTo 见 done 退。
// goroutine 安全:tunnel 内 cmd/reply channel 串行化(SetDeadline no-op 是预期 —— DeadlineEnhance 用 goroutine
// +timer 竞争式实现 deadline,不依赖本 conn 的 SetReadDeadline)。
type speedcatPacketConn struct {
	tunnel *client.UdpTunnel
	ctx    context.Context
	cancel context.CancelFunc
}

// newSpeedcatPacketConn 建桥接 + 绑定生命周期 ctx。
func newSpeedcatPacketConn(tunnel *client.UdpTunnel) *speedcatPacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &speedcatPacketConn{tunnel: tunnel, ctx: ctx, cancel: cancel}
}

// ReadFrom 收一个 UDP 报文(入向):tunnel.RecvFrom → 拷进 mihomo 给的缓冲 p(UDP datagram ≤ 64K,pool
// 缓冲足够)。隧道关(对端关 / task 退 / Close)→ ErrTunnelClosed 返 error(EOF 语义,mihomo NAT 据此回收)。
func (c *speedcatPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	addr, data, err := c.tunnel.RecvFrom(c.ctx)
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, data)
	return n, speedcatAddrToNetAddr(addr), nil
}

// WriteTo 发一个 UDP 报文(出向):net.Addr → wire.Addr(易踩坑 #2:domain→0x02 / IPv6→0x03,与 SOCKS5 不同)
// → tunnel.SendTo。net.Addr 通常是 *net.UDPAddr(mihomo 按 NAT 目标填);域名目标走 fallback String() 解析。
func (c *speedcatPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	a, err := netAddrToSpeedcat(addr)
	if err != nil {
		return 0, err
	}
	if err := c.tunnel.SendTo(c.ctx, a, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close 终结 UDP 关联:取消 ctx(kick 阻塞的 RecvFrom/SendTo)+ tunnel.Close(关 done → relay task 退 → 关底层 conn)。
func (c *speedcatPacketConn) Close() error {
	c.cancel()
	return c.tunnel.Close()
}

// LocalAddr 返占位 UDP 零地址(mihomo 链路展示用;本桥接无真实本地 UDP socket,数据走 speedcat 隧道)。
func (c *speedcatPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline / SetReadDeadline / SetWriteDeadline no-op —— DeadlineEnhancePacketConn 用 goroutine+timer
// 竞争式实现 deadline,不调本方法做真实中断(NewPacketConn 对「非 syscall.Conn 的 outbound」一律叠该 wrapper,
// base.go:344 注:「most conn from outbound can't handle readDeadline correctly」)。
func (c *speedcatPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *speedcatPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *speedcatPacketConn) SetWriteDeadline(time.Time) error { return nil }

// netAddrToSpeedcat net.Addr → wire.Addr(出向:WriteTo 收到的目标)。优先 *net.UDPAddr/*net.TCPAddr 直取 IP;
// fallback SplitHostPort(host 若 IP→按族 / 否则 domain;远端 DNS 解析交给 Rust server,避免本地 DNS 泄漏 09 §3)。
// atype 映射 domain→0x02 / IPv6→0x03(**与 SOCKS5 atype 不同**,易踩坑 #2)。
func netAddrToSpeedcat(addr net.Addr) (wire.Addr, error) {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return speedcatAddrFromIP(v.IP, v.Port), nil
	case *net.TCPAddr:
		return speedcatAddrFromIP(v.IP, v.Port), nil
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return wire.Addr{}, fmt.Errorf("speedcat: 无法解析 UDP 目标地址 %q: %w", addr.String(), err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return wire.Addr{}, fmt.Errorf("speedcat: UDP 目标端口非法 %q: %w", portStr, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		return speedcatAddrFromIP(ip, int(port)), nil
	}
	if len(host) > 255 {
		return wire.Addr{}, fmt.Errorf("speedcat: UDP 目标域名过长(>255):%s", host)
	}
	return wire.Addr{Type: wire.AddrTypeDomain, Domain: host, Port: uint16(port)}, nil
}

// speedcatAddrFromIP net.IP + port → wire.Addr(规约 4-in-6:To4 守 As4;非 IPv4 走 IPv6 As16)。
func speedcatAddrFromIP(ip net.IP, port int) wire.Addr {
	a := wire.Addr{Port: uint16(port)}
	if v4 := ip.To4(); v4 != nil {
		a.Type = wire.AddrTypeIPv4
		copy(a.IPv4[:], v4)
	} else {
		a.Type = wire.AddrTypeIPv6
		copy(a.IPv6[:], ip.To16())
	}
	return a
}

// speedcatAddrToNetAddr wire.Addr → net.Addr(入向:ReadFrom 返的源地址,供 mihomo 链路展示 + NAT)。
// IPv4/IPv6 填真 IP;domain 源(罕见)返零 IP + port(NAT 不据此路由)。
func speedcatAddrToNetAddr(a wire.Addr) net.Addr {
	switch a.Type {
	case wire.AddrTypeIPv4:
		return &net.UDPAddr{IP: a.IPv4[:], Port: int(a.Port)}
	case wire.AddrTypeIPv6:
		return &net.UDPAddr{IP: a.IPv6[:], Port: int(a.Port)}
	default:
		return &net.UDPAddr{IP: net.IPv4zero, Port: int(a.Port)}
	}
}
