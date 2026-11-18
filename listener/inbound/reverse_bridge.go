package inbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/muxcool"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/tunnel"
)

// ReverseBridgeOption —— 反向代理 Bridge 侧 listener 配置。
// 不监听端口:主动经 `portal` 指定的 VLESS 出站拨到 Portal 建反连隧道,
// 把 Portal 反向复用回来的子流按其 target 交给 mihomo tunnel(规则决定出口,通常 DIRECT=本机内网)。
type ReverseBridgeOption struct {
	BaseOption
	Portal string `inbound:"portal"` // 引用 proxies: 里的一个 VLESS 出站名(拨到 Xray/mihomo Portal)
}

func (o ReverseBridgeOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type ReverseBridge struct {
	*Base
	config *ReverseBridgeOption
	cancel context.CancelFunc
}

func NewReverseBridge(options *ReverseBridgeOption) (*ReverseBridge, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &ReverseBridge{Base: base, config: options}, nil
}

// Config implements constant.InboundListener
func (r *ReverseBridge) Config() C.InboundConfig { return r.config }

// Address implements constant.InboundListener
func (r *ReverseBridge) Address() string { return "reverse-bridge->" + r.config.Portal }

// Close implements constant.InboundListener
func (r *ReverseBridge) Close() error {
	if r.cancel != nil {
		r.cancel()
	}
	return nil
}

// Listen implements constant.InboundListener —— 必须非阻塞:起 goroutine 维护反连。
func (r *ReverseBridge) Listen(t C.Tunnel) error {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go r.loop(ctx, t)
	log.Infoln("ReverseBridge[%s] started, portal proxy = %s", r.Name(), r.config.Portal)
	return nil
}

func (r *ReverseBridge) loop(ctx context.Context, t C.Tunnel) {
	for {
		if ctx.Err() != nil {
			return
		}
		err := r.runOnce(ctx, t)
		if ctx.Err() != nil {
			return
		}
		log.Warnln("ReverseBridge[%s] tunnel down (%v); reconnect in 3s", r.Name(), err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (r *ReverseBridge) runOnce(ctx context.Context, t C.Tunnel) error {
	// 惰性按名解析 VLESS 出站(应对 proxy reload / 启动顺序)。
	p, ok := tunnel.Proxies()[r.config.Portal]
	if !ok {
		return fmt.Errorf("portal proxy %q not found", r.config.Portal)
	}
	// 解包:config 里的 proxy 被 autoCloseProxyAdapter 包了一层(base.go),
	// InnerProxyAdapter()(patch 0004)取回内层具体适配器,再断言成 *Vless。
	pa := p.Adapter()
	if inner, ok := pa.(interface {
		InnerProxyAdapter() outbound.ProxyAdapter
	}); ok {
		pa = inner.InnerProxyAdapter()
	}
	v, ok := pa.(*outbound.Vless)
	if !ok {
		return fmt.Errorf("portal proxy %q is not a vless outbound (got %T)", r.config.Portal, pa)
	}
	conn, err := v.DialReverse(ctx)
	if err != nil {
		return err
	}
	disp := &bridgeDispatcher{tunnel: t, additions: r.Additions()}
	sw := muxcool.NewServerWorker(conn, disp, func([]byte) {}) // 心跳:收到即保活,无需处理
	done := make(chan error, 1)
	go func() { done <- sw.Run() }()
	select {
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	case e := <-done:
		return e
	}
}

// bridgeDispatcher —— 把 Portal 反向来的子流按 target 造成"新入站请求"塞进 mihomo tunnel。
// 不自己拨号:用 net.Pipe 桥接,一端给 tunnel(规则决定出口),一端还给 ServerWorker 收发。
type bridgeDispatcher struct {
	tunnel    C.Tunnel
	additions []inbound.Addition
}

func (d *bridgeDispatcher) DialTarget(network muxcool.TargetNetwork, addr muxcool.Address, port uint16) (net.Conn, error) {
	hostport := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
	// UDP 子流:用 mihomo 的 dialer 拨目标 UDP(连接式,Read/Write 保数据报边界)。
	// 必须用 dialer(内部走 mihomo 解析器)——net.Dial 域名会触发被禁用的 Go 默认解析器而 panic。
	// MVP 落地直连,不经 mihomo UDP 路由(Bridge 即内网网关);够用于 DNS/QUIC 到固定目标。
	if network == muxcool.NetworkUDP {
		return dialer.DialContext(context.Background(), "udp", hostport)
	}
	target := socks5.ParseAddr(hostport)
	if target == nil {
		return nil, fmt.Errorf("reverse-bridge: bad target %s", hostport)
	}
	left, right := net.Pipe()
	go d.tunnel.HandleTCPConn(inbound.NewSocket(target, right, C.TUNNEL, d.additions...))
	return left, nil
}

var _ C.InboundListener = (*ReverseBridge)(nil)
