// socks5.go —— SOCKS5 入口(CONNECT + UDP_ASSOCIATE)。RFC 1928。
//
// HandleConn 处理一条 SOCKS5 客户端连接:greeting(no-auth)→ request 解析 →
//   - CONNECT(0x01):[Client.Dial] → 成功 reply → [StreamConn.Relay] 双向桥接。
//   - UDP_ASSOCIATE(0x03):bind 本地 UDP → reply BND → [Client.DialUDP] → SOCKS5 UDP relay(本地 UDP ↔ 隧道)。
//
// # ATYP 映射(SOCKS5 ↔ speedcat,**易踩坑 #2**:两协议 atype 取值不同!)
//
//	SOCKS5 IPv4 0x01 → speedcat IPv4 0x01(相同)
//	SOCKS5 domain 0x03 → speedcat domain 0x02(不同!VLESS/v2ray 风格)
//	SOCKS5 IPv6 0x04 → speedcat IPv6 0x03(不同!)
//
// 对照 Rust speedcat-client/src/socks5.rs(同款映射;speedcat Addr 域名=0x02 是 VLESS 习惯)。
// UDP_ASSOCIATE 的 SOCKS5 UDP 头编解码见 [parseSocks5UDP] / [encodeSocks5UDP](RFC 1928 §7,FRAG 恒 0)。
//
// **panic-free**:解析/IO 错 → reply 失败码 + 返 error(被 mihomo import 的库不 panic)。

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// SOCKS5 常量(RFC 1928)。
const (
	socks5Version  byte = 0x05
	socks5NoAuth   byte = 0x00 // METHOD:无认证(PSK 在 speedcat 握手层,SOCKS5 层不重复)
	socks5CmdTCP   byte = 0x01 // CONNECT
	socks5CmdUDP   byte = 0x03 // UDP ASSOCIATE
	socks5AtypIPv4 byte = 0x01
	socks5AtypDom  byte = 0x03 // SOCKS5 域名(注意:与 speedcat 0x02 不同)
	socks5AtypIPv6 byte = 0x04 // SOCKS5 IPv6(注意:与 speedcat 0x03 不同)
)

// SOCKS5 reply 码(RFC 1928 §4.2 REP)。
const (
	repSuccess          byte = 0x00
	repGeneralFailure   byte = 0x01
	repCmdNotSupported  byte = 0x07
	repAtypNotSupported byte = 0x08
)

// ErrSOCKS5 SOCKS5 协议层错误(解析失败 / 不支持的 CMD/ATYP)。
var ErrSOCKS5 = errors.New("client/socks5: 协议错误")

// HandleConn 处理一条 SOCKS5 连接(CONNECT)。ctx 透传给 Dial(SOCKS5 客户端 deadline/取消级联到 speedcat
// 拨号)。c = 已配置的 speedcat Client(Dial 用)。返回时连接已 Close(成功 relay 结束 / 失败 reply 后)。
// 错误供 accept loop 记日志(非致命)。
func HandleConn(ctx context.Context, socks net.Conn, c *Client) error {
	defer socks.Close()

	// 1) greeting:[VER][NMETHODS][METHODS...]. 选 no-auth(0x00);不支持认证方法 → 失败。
	if err := socks5Greeting(socks); err != nil {
		return fmt.Errorf("%w: greeting: %v", ErrSOCKS5, err)
	}

	// 2) request:[VER][CMD][RSV][ATYP][DST.ADDR][DST.PORT].
	cmd, target, err := socks5ReadRequest(socks)
	if err != nil {
		return fmt.Errorf("%w: request: %v", ErrSOCKS5, err)
	}

	switch cmd {
	case socks5CmdTCP:
		return handleConnect(ctx, socks, c, target)
	case socks5CmdUDP:
		return handleUDP(ctx, socks, c, target)
	default:
		_ = socks5Reply(socks, repCmdNotSupported, nil)
		return fmt.Errorf("%w: 不支持的 CMD 0x%02x", ErrSOCKS5, cmd)
	}
}

// handleConnect:Dial speedcat → reply 成功 → relay。
func handleConnect(ctx context.Context, socks net.Conn, c *Client, target wire.Addr) error {
	sc, err := c.Dial(ctx, target) // ctx 透传 SOCKS5 客户端 deadline/取消到 speedcat 拨号
	if err != nil {
		_ = socks5Reply(socks, repGeneralFailure, nil)
		return err
	}
	defer sc.Close()
	// reply 成功:BND.ADDR/PORT 用本地零地址(客户端一般不校验 BND;Rust 同款回复 0.0.0.0:0)。
	if err := socks5Reply(socks, repSuccess, nil); err != nil {
		return fmt.Errorf("%w: reply: %v", ErrSOCKS5, err)
	}
	// 双向桥接(SOCKS5 客户端 TCP ↔ speedcat conn)。relay 结束 = 连接生命周期结束。
	return sc.Relay(socks)
}

// socks5Greeting 读 greeting 并回 no-auth。
func socks5Greeting(socks io.ReadWriter) error {
	var head [2]byte
	if _, err := io.ReadFull(socks, head[:]); err != nil {
		return err
	}
	if head[0] != socks5Version {
		return fmt.Errorf("版本 0x%02x 非 0x05", head[0])
	}
	nMethods := int(head[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(socks, methods); err != nil {
		return err
	}
	// no-auth(0x00)须在客户端 METHODS 中;否则回 0xFF(无可用方法)。
	accept := false
	for _, m := range methods {
		if m == socks5NoAuth {
			accept = true
			break
		}
	}
	if !accept {
		_, _ = socks.Write([]byte{socks5Version, 0xFF})
		return errors.New("客户端不接受 no-auth")
	}
	_, err := socks.Write([]byte{socks5Version, socks5NoAuth})
	return err
}

// socks5ReadRequest 读 request → (CMD, speedcat target Addr)。ATYP 映射见模块头。
func socks5ReadRequest(socks io.Reader) (byte, wire.Addr, error) {
	var head [4]byte // [VER][CMD][RSV][ATYP]
	if _, err := io.ReadFull(socks, head[:]); err != nil {
		return 0, wire.Addr{}, err
	}
	if head[0] != socks5Version {
		return 0, wire.Addr{}, fmt.Errorf("版本 0x%02x 非 0x05", head[0])
	}
	cmd := head[1]
	atyp := head[3]
	var target wire.Addr
	switch atyp {
	case socks5AtypIPv4:
		var buf [4 + 2]byte
		if _, err := io.ReadFull(socks, buf[:]); err != nil {
			return 0, wire.Addr{}, err
		}
		target.Type = wire.AddrTypeIPv4
		target.IPv4 = [4]byte{buf[0], buf[1], buf[2], buf[3]}
		target.Port = binary.BigEndian.Uint16(buf[4:6])
	case socks5AtypDom:
		var lp [1]byte
		if _, err := io.ReadFull(socks, lp[:]); err != nil {
			return 0, wire.Addr{}, err
		}
		l := int(lp[0])
		dom := make([]byte, l+2)
		if _, err := io.ReadFull(socks, dom); err != nil {
			return 0, wire.Addr{}, err
		}
		// SOCKS5 domain(0x03)→ speedcat domain(0x02)。
		target.Type = wire.AddrTypeDomain
		target.Domain = string(dom[:l])
		target.Port = binary.BigEndian.Uint16(dom[l : l+2])
	case socks5AtypIPv6:
		var buf [16 + 2]byte
		if _, err := io.ReadFull(socks, buf[:]); err != nil {
			return 0, wire.Addr{}, err
		}
		// SOCKS5 IPv6(0x04)→ speedcat IPv6(0x03)。
		target.Type = wire.AddrTypeIPv6
		copy(target.IPv6[:], buf[:16])
		target.Port = binary.BigEndian.Uint16(buf[16:18])
	default:
		return 0, wire.Addr{}, fmt.Errorf("不支持的 ATYP 0x%02x", atyp)
	}
	return cmd, target, nil
}

// socks5Reply 写 reply:[VER][REP][RSV=0][ATYP][BND.ADDR][BND.PORT]。
// bnd=nil → 用 0.0.0.0:0(ATYP=IPv4,占位;客户端通常不校验)。
func socks5Reply(socks io.Writer, rep byte, bnd *wire.Addr) error {
	var buf []byte
	buf = append(buf, socks5Version, rep, 0x00) // VER/REP/RSV
	if bnd == nil {
		buf = append(buf, socks5AtypIPv4, 0, 0, 0, 0, 0, 0) // ATYP=IPv4 + 0.0.0.0:0
	} else {
		// 按 SOCKS5 atyp 编码 BND(域名→0x03 / IPv6→0x04,SOCKS5 侧取值)。
		switch bnd.Type {
		case wire.AddrTypeIPv4:
			buf = append(buf, socks5AtypIPv4)
			buf = append(buf, bnd.IPv4[:]...)
		case wire.AddrTypeIPv6:
			buf = append(buf, socks5AtypIPv6)
			buf = append(buf, bnd.IPv6[:]...)
		case wire.AddrTypeDomain:
			buf = append(buf, socks5AtypDom, byte(len(bnd.Domain)))
			buf = append(buf, bnd.Domain...)
		}
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], bnd.Port)
		buf = append(buf, port[:]...)
	}
	_, err := socks.Write(buf)
	return err
}

// handleUDP UDP_ASSOCIATE(RFC 1928 §6/§7;Stage 2):bind 本地 UDP → reply BND → [Client.DialUDP]
// → SOCKS5 UDP relay(本地 UDP ↔ 隧道)。**关联绑定到 TCP 控制连接**:客户端关 TCP → 终结 relay
// (RFC 1928:UDP ASSOCIATE 与 TCP 控制连接生命周期绑定)。对照 Rust handle_socks5_udp。
//
// **SOCKS5 UDP 头(RFC 1928 §7):** `[RSV:2][FRAG:1][ATYP:1][DST.ADDR][DST.PORT][DATA]`。
// 我们**不支持 SOCKS5 层分片**(FRAG 恒 0;收 FRAG≠0 丢 —— 分片在 QUIC datagram 层做,非 SOCKS5 层)。
func handleUDP(ctx context.Context, socks net.Conn, c *Client, dst wire.Addr) error {
	// bind 本地 UDP socket(SOCKS5 客户端把 UDP 报文发到此);BND = 此 socket 地址(RFC 1928 §6)。
	udpSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = socks5Reply(socks, repGeneralFailure, nil)
		return err
	}
	defer udpSock.Close()

	// reply success + BND(UDP 中继端口)。BND 用真实绑定地址(V4);客户端据此发 UDP。
	bndUDP, ok := udpSock.LocalAddr().(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("%w: UDP local addr 非 *UDPAddr", ErrSOCKS5)
	}
	bnd := wire.Addr{Type: wire.AddrTypeIPv4, IPv4: ipv4Bytes(bndUDP.IP), Port: uint16(bndUDP.Port)}
	if err := socks5Reply(socks, repSuccess, &bnd); err != nil {
		return fmt.Errorf("%w: reply BND: %v", ErrSOCKS5, err)
	}

	// 经 speedcat 建 UDP 关联(dst 进 UdpAssociate 帧;客户端通常给 0.0.0.0:0,服务端按每报文
	// header 自带目标路由,此 dst 仅元信息)。dial 失败 → 关连接(reply 已发成功,不重发失败码;对照 Rust)。
	tunnel, err := c.DialUDP(ctx, dst)
	if err != nil {
		return err
	}
	defer tunnel.Close()

	// 控制连接关闭 → 终结 UDP 关联。relayCtx cancel → 两 relay goroutine 退。
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 首个入站 UDP 包的源(SOCKS5 客户端地址);回程 send_to 此源。RFC 1928 实践:同一关联回给首个发包者。
	var (
		clientMu   sync.Mutex
		clientAddr *net.UDPAddr
	)
	setClient := func(a *net.UDPAddr) {
		clientMu.Lock()
		clientAddr = a
		clientMu.Unlock()
	}
	getClient := func() *net.UDPAddr {
		clientMu.Lock()
		defer clientMu.Unlock()
		return clientAddr
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// SOCKS5 客户端 → 目标:UDP recv → 解 SOCKS5 UDP 头 → tunnel.SendTo。
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, src, err := udpSock.ReadFromUDP(buf)
			if err != nil {
				return // socket 关 → 终。
			}
			setClient(src)
			target, data, ok := parseSocks5UDP(buf[:n])
			if !ok {
				continue // FRAG≠0 / 畸形 → 丢(RFC 1928 §7:不支持分片则丢)。
			}
			if err := tunnel.SendTo(relayCtx, target, data); err != nil {
				return // 隧道关 → 终。
			}
		}
	}()

	// 目标 → SOCKS5 客户端:tunnel.RecvFrom → 包 SOCKS5 UDP 头 → send_to 首源。
	go func() {
		defer wg.Done()
		for {
			addr, data, err := tunnel.RecvFrom(relayCtx)
			if err != nil {
				return // 隧道关 → 终。
			}
			ca := getClient()
			if ca == nil {
				continue // 尚无客户端源(未收到首个入站包)→ 丢回程。
			}
			pkt := encodeSocks5UDP(addr, data)
			if _, err := udpSock.WriteToUDP(pkt, ca); err != nil {
				return
			}
		}
	}()

	// TCP 控制连接关闭 → 终结 UDP 关联(RFC 1928:UDP ASSOCIATE 与控制连接生命周期绑定)。
	// 阻塞读控制流(UDP 关联期控制连接不应有数据);忽略杂散字节(对照 Rust)。
	ctrlBuf := make([]byte, 16)
	for {
		if _, err := socks.Read(ctrlBuf); err != nil {
			break // 控制连接关(EOF / 错)→ 终结。
		}
		// 忽略控制流上的杂散字节(UDP 关联期控制连接不应有数据)。
	}
	cancel() // kick relay 两 goroutine(ReadFromUDP/RecvFrom via ctx 不直接中断,但 socket 关 + tunnel 关兜底)
	udpSock.Close()
	tunnel.Close()
	wg.Wait()
	return nil
}

// ipv4Bytes 把 net.IP(可能 4/16B)规约成 4B IPv4(ListenUDP 绑 127.0.0.1 → 必 V4,To4 兜底)。
func ipv4Bytes(ip net.IP) [4]byte {
	var b [4]byte
	if v4 := ip.To4(); v4 != nil {
		copy(b[:], v4)
	}
	return b
}

// parseSocks5UDP 解 SOCKS5 UDP 头 `[RSV:2][FRAG:1][ATYP:1][DST.ADDR][DST.PORT][DATA]` → (speedcat target, data)。
// RSV 非 0 / FRAG≠0 / 畸形 → ok=false(调用方丢包;RFC 1928 §7)。ATYP 映射 SOCKS5→speedcat(易踩坑 #2)。
func parseSocks5UDP(buf []byte) (wire.Addr, []byte, bool) {
	if len(buf) < 4 {
		return wire.Addr{}, nil, false
	}
	if buf[0] != 0 || buf[1] != 0 { // RSV 须 0
		return wire.Addr{}, nil, false
	}
	if buf[2] != 0 { // FRAG 须 0(不支持 SOCKS5 层分片)
		return wire.Addr{}, nil, false
	}
	atyp := buf[3]
	var target wire.Addr
	var off int
	switch atyp {
	case socks5AtypIPv4:
		if len(buf) < 4+4+2 {
			return wire.Addr{}, nil, false
		}
		// SOCKS5 IPv4(0x01)→ speedcat IPv4(0x01,相同)。
		target.Type = wire.AddrTypeIPv4
		target.IPv4 = [4]byte{buf[4], buf[5], buf[6], buf[7]}
		target.Port = binary.BigEndian.Uint16(buf[8:10])
		off = 10
	case socks5AtypDom:
		if len(buf) < 5 {
			return wire.Addr{}, nil, false
		}
		l := int(buf[4])
		if len(buf) < 5+l+2 {
			return wire.Addr{}, nil, false
		}
		// SOCKS5 domain(0x03)→ speedcat domain(0x02,不同)。
		target.Type = wire.AddrTypeDomain
		target.Domain = string(buf[5 : 5+l])
		target.Port = binary.BigEndian.Uint16(buf[5+l : 5+l+2])
		off = 5 + l + 2
	case socks5AtypIPv6:
		if len(buf) < 4+16+2 {
			return wire.Addr{}, nil, false
		}
		// SOCKS5 IPv6(0x04)→ speedcat IPv6(0x03,不同)。
		target.Type = wire.AddrTypeIPv6
		copy(target.IPv6[:], buf[4:20])
		target.Port = binary.BigEndian.Uint16(buf[20:22])
		off = 22
	default:
		return wire.Addr{}, nil, false
	}
	return target, buf[off:], true
}

// encodeSocks5UDP 编 SOCKS5 UDP 头(speedcat addr + data → `[RSV:2][FRAG:0][ATYP:1][DST.ADDR][DST.PORT][DATA]`)。
// ATYP 映射 speedcat→SOCKS5(易踩坑 #2 的逆映射)。回程发给 SOCKS5 客户端(对照 Rust encode_socks5_udp)。
func encodeSocks5UDP(addr wire.Addr, data []byte) []byte {
	out := make([]byte, 0, 3+1+maxAddrWireLen(addr)+2+len(data))
	out = append(out, 0, 0, 0) // RSV/RSV/FRAG(恒 0)
	switch addr.Type {
	case wire.AddrTypeIPv4:
		out = append(out, socks5AtypIPv4)
		out = append(out, addr.IPv4[:]...)
	case wire.AddrTypeDomain:
		out = append(out, socks5AtypDom, byte(len(addr.Domain)))
		out = append(out, addr.Domain...)
	case wire.AddrTypeIPv6:
		out = append(out, socks5AtypIPv6)
		out = append(out, addr.IPv6[:]...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], addr.Port)
	out = append(out, port[:]...)
	out = append(out, data...)
	return out
}

// maxAddrWireLen SOCKS5 地址段最大字节数(域名 1B 长度 + 255B + atype;用于 encode 预分配上界)。
func maxAddrWireLen(addr wire.Addr) int {
	switch addr.Type {
	case wire.AddrTypeDomain:
		return 1 + 1 + len(addr.Domain) // atyp + len + domain
	case wire.AddrTypeIPv4:
		return 1 + 4
	case wire.AddrTypeIPv6:
		return 1 + 16
	default:
		return 1
	}
}
