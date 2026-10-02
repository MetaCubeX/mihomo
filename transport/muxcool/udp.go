package muxcool

import (
	"net"
	"strconv"
	"sync"
	"time"
)

// udpPacket —— 一个入站 UDP 数据报(带 source,供 ReadFrom 回填)。
type udpPacket struct {
	src  net.Addr
	data []byte
}

// NewPacketConn 返回一个反向 UDP 的 net.PacketConn(全锥):一个 PacketConn 内,
// 每个不同 target 开一条独立 Mux.cool UDP 子流(与 Xray reverse 的 per-target 子流一致),
// 所有子流的回程数据报汇聚到共享队列,ReadFrom 带回各自 source。
func (w *ClientWorker) NewPacketConn() *muxPacketConn {
	return &muxPacketConn{
		w:        w,
		recv:     make(chan udpPacket, 512),
		sessions: make(map[string]*clientSession),
		closed:   make(chan struct{}),
	}
}

type muxPacketConn struct {
	w    *ClientWorker
	recv chan udpPacket // 所有子流的入站数据报汇聚于此

	mu       sync.Mutex
	sessions map[string]*clientSession // targetKey(addr.String())→ 子流
	closed   chan struct{}
	closeOn  sync.Once

	dmu      sync.Mutex
	deadline time.Time
}

// WriteTo 把 p 发到 addr:按 target 复用/新建 UDP 子流,数据报封成 UDP Keep 帧发出。
func (c *muxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	a, port := netAddrToMux(addr)
	key := addr.String()

	c.mu.Lock()
	cs := c.sessions[key]
	newSession := cs == nil
	if newSession {
		id := c.w.allocID()
		cs = &clientSession{id: id, udp: true, sink: c.recv, target: addr, closed: make(chan struct{})}
		c.w.addSession(cs)
		c.sessions[key] = cs
	}
	c.mu.Unlock()

	if newSession {
		// 新 target:先发一个 New(UDP, target) 注册子流。
		nm := &FrameMetadata{SessionID: cs.id, Status: StatusNew, Network: NetworkUDP, Address: a, Port: port}
		if err := c.w.writeFrame(nm, nil); err != nil {
			return 0, err
		}
	}
	// 数据报 → UDP Keep 帧(带 network=UDP + 地址)。
	c.w.writeMu.Lock()
	m := &FrameMetadata{SessionID: cs.id, Status: StatusKeep, Network: NetworkUDP, Address: a, Port: port, Option: OptionData}
	err := WriteFrame(c.w.link, m, p)
	c.w.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom 从共享队列取一个回程数据报,返回其 source(对应子流的 target)。
func (c *muxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.dmu.Lock()
	dl := c.deadline
	c.dmu.Unlock()
	var timer <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timer = t.C
	}
	select {
	case pkt := <-c.recv:
		n := copy(p, pkt.data)
		return n, pkt.src, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, timeoutErr{}
	}
}

func (c *muxPacketConn) Close() error {
	c.closeOn.Do(func() {
		close(c.closed)
		c.mu.Lock()
		sessions := c.sessions
		c.sessions = map[string]*clientSession{}
		c.mu.Unlock()
		for _, cs := range sessions {
			c.w.writeEnd(cs.id, false)
			c.w.finish(cs)
		}
	})
	return nil
}

func (c *muxPacketConn) LocalAddr() net.Addr { return muxAddr{} }

func (c *muxPacketConn) SetDeadline(t time.Time) error {
	c.dmu.Lock()
	c.deadline = t
	c.dmu.Unlock()
	return nil
}
func (c *muxPacketConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *muxPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// netAddrToMux 把 net.Addr 转成 Mux.cool 地址+端口(IP 直用,否则按 host:port 解析,支持域名)。
func netAddrToMux(addr net.Addr) (Address, uint16) {
	if ua, ok := addr.(*net.UDPAddr); ok {
		return Address{IP: ua.IP}, uint16(ua.Port)
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return Address{IsDomain: true, Domain: addr.String()}, 0
	}
	port, _ := strconv.Atoi(portStr)
	return AddrFromString(host), uint16(port)
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "muxcool: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
