// Package reverse —— 反向代理 Portal 侧的运行时注册表。
//
// Portal 由两半组成、经此包用一个 tag 关联:
//   - reverse-portal listener(listener/inbound):接受 Bridge 的 VLESS-Rvs 反连,
//     在连接上跑 muxcool.ClientWorker(Portal=Mux.cool 客户端 + 心跳),注册到本表。
//   - reverse-portal outbound(adapter/outbound):用户流量按 routing 命中它,
//     DialContext 经本表挑一条活跃 ClientWorker 开子流(OpenStream)下发到 Bridge。
package reverse

import (
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/transport/muxcool"
)

type picker struct {
	mu      sync.Mutex
	workers []*muxcool.ClientWorker
	next    int // round-robin 游标
}

var registry = struct {
	mu sync.Mutex
	m  map[string]*picker
}{m: make(map[string]*picker)}

func getPicker(tag string) *picker {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	p := registry.m[tag]
	if p == nil {
		p = &picker{}
		registry.m[tag] = p
	}
	return p
}

func (p *picker) add(w *muxcool.ClientWorker) {
	p.mu.Lock()
	p.workers = append(p.workers, w)
	p.mu.Unlock()
}

func (p *picker) remove(w *muxcool.ClientWorker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, x := range p.workers {
		if x == w {
			p.workers = append(p.workers[:i], p.workers[i+1:]...)
			break
		}
	}
}

// pick 轮询选一条【活跃】worker(跳过已关闭/draining),多 Bridge 接同一 tag 时负载均衡。
func (p *picker) pick() *muxcool.ClientWorker {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.workers)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		w := p.workers[p.next%n]
		p.next++
		if w.IsActive() {
			return w
		}
	}
	return nil // 全部不可用
}

// RegisterPortalConn 在一条已完成 VLESS-Rvs 握手的 Bridge 连接上跑 Portal 端 Mux.cool 客户端,
// 注册到 tag 对应的 picker,阻塞直到隧道关闭。由 reverse-portal listener 每条反连调用。
func RegisterPortalConn(tag string, conn net.Conn) {
	cw := muxcool.NewClientWorker(conn)
	go cw.Run()
	_ = cw.StartControl(0) // 0=默认 10s 心跳
	p := getPicker(tag)
	p.add(cw)
	defer p.remove(cw)
	<-cw.Done()
}

// Open 为 tag 挑一条活跃 worker,开一条到 target 的用户子流。reverse-portal outbound 调用。
func Open(tag string, network muxcool.TargetNetwork, addr muxcool.Address, port uint16) (net.Conn, error) {
	w := getPicker(tag).pick()
	if w == nil {
		return nil, fmt.Errorf("reverse portal %q: no active bridge tunnel", tag)
	}
	return w.OpenStream(network, addr, port)
}

// NewPacketConn 为 tag 挑一条活跃 worker,返回一个全锥 UDP PacketConn(内部按 target 开多子流)。
func NewPacketConn(tag string) (net.PacketConn, error) {
	w := getPicker(tag).pick()
	if w == nil {
		return nil, fmt.Errorf("reverse portal %q: no active bridge tunnel", tag)
	}
	return w.NewPacketConn(), nil
}
