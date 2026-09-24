package muxcool

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"
)

// ClientWorker —— 在一条(VLESS-Rvs 隧道)明文流上跑 Mux.cool 客户端。
//
// 角色:Portal 侧。Portal 是 Mux.cool 客户端——主动开子流承载用户流量(New/Keep/End),
// 并开一条控制子流周期发 Control 心跳。回程(Keep/End)由 Run 读环解复用回各子流。
//
// 与 ServerWorker 对称:ServerWorker 被动收 New 并落地;ClientWorker 主动开 New。
type ClientWorker struct {
	link io.ReadWriteCloser

	writeMu  sync.Mutex
	mu       sync.Mutex
	nextID   uint16
	total    uint64 // 累计分配的子流数(含控制流),用于 >256 转 DRAIN
	draining bool
	sessions map[uint16]*clientSession

	closeOnce sync.Once
	done      chan struct{}
}

type clientSession struct {
	id     uint16
	udp    bool             // UDP 子流:Keep 数据按数据报推入 sink(保边界+带 source),不走 inW
	inW    *bufPipe         // 仅 TCP:Run 读到该子流的 Keep 数据写这里(带缓冲,缓解 HoL)
	sink   chan udpPacket   // 仅 UDP:入站数据报汇聚到所属 PacketConn 的共享队列(带 source)
	target net.Addr         // 仅 UDP:本子流的固定 target(回填为 ReadFrom 的 source)
	closed chan struct{}
	once   sync.Once
}

// NewClientWorker 构造。调用方应 go w.Run() 跑解复用读环,并按需 OpenStream / StartControl。
func NewClientWorker(link io.ReadWriteCloser) *ClientWorker {
	return &ClientWorker{
		link:     link,
		nextID:   0,
		sessions: make(map[uint16]*clientSession),
		done:     make(chan struct{}),
	}
}

// Done 在 worker 关闭(link 断开)后被 close,供上层阻塞等待隧道结束。
func (w *ClientWorker) Done() <-chan struct{} { return w.done }

// IsActive 报告该隧道是否可继续接新用户子流(未关闭、未 draining)。picker 据此挑选。
func (w *ClientWorker) IsActive() bool {
	select {
	case <-w.done:
		return false
	default:
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.draining
}

// Run 跑解复用读环,直到 link 出错/关闭。返回时清理所有子流。
func (w *ClientWorker) Run() error {
	defer w.closeAll()
	for {
		m, data, err := ReadFrame(w.link)
		if err != nil {
			return err
		}
		switch m.Status {
		case StatusKeep:
			cs := w.getSession(m.SessionID)
			if cs == nil {
				// 未知会话(已关):回 End 通知对端关闭(对齐 Xray client.go:354)。
				w.writeEnd(m.SessionID, false)
			} else if len(data) > 0 {
				if cs.udp {
					cp := make([]byte, len(data))
					copy(cp, data)
					select {
					case cs.sink <- udpPacket{src: cs.target, data: cp}:
					default: // 队列满则丢(UDP 语义可丢)
					}
				} else {
					cs.inW.Write(data)
				}
			}
		case StatusEnd:
			if cs := w.getSession(m.SessionID); cs != nil {
				w.finish(cs)
			}
		case StatusNew:
			// Bridge 是 mux 服务端,不应主动开子流;忽略。
		case StatusKeepAlive:
			// 丢弃。
		}
	}
}

// -------- 帧写(加锁)--------

func (w *ClientWorker) writeFrame(m *FrameMetadata, data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return WriteFrame(w.link, m, data)
}

func (w *ClientWorker) writeData(id uint16, data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return WriteData(w.link, id, data)
}

func (w *ClientWorker) writeEnd(id uint16, hasErr bool) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return WriteEnd(w.link, id, hasErr)
}

// -------- 会话表 --------

func (w *ClientWorker) allocID() uint16 {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total++
	if w.total > 256 { // 对齐 Xray:累计连接 >256 转 DRAIN,提示对端另建隧道
		w.draining = true
	}
	for {
		w.nextID++
		if w.nextID == 0 {
			continue // 跳过 0
		}
		if _, exists := w.sessions[w.nextID]; !exists {
			return w.nextID
		}
	}
}

func (w *ClientWorker) addSession(s *clientSession) {
	w.mu.Lock()
	w.sessions[s.id] = s
	w.mu.Unlock()
}

func (w *ClientWorker) getSession(id uint16) *clientSession {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sessions[id]
}

func (w *ClientWorker) removeSession(id uint16) {
	w.mu.Lock()
	delete(w.sessions, id)
	w.mu.Unlock()
}

func (w *ClientWorker) finish(s *clientSession) {
	s.once.Do(func() {
		w.removeSession(s.id)
		if s.inW != nil {
			s.inW.Close()
		}
		if s.closed != nil {
			close(s.closed) // 通知 UDP 读者收尾;sink 是共享队列不在此关(避免与 Run 的 send 竞争)
		}
	})
}

func (w *ClientWorker) closeAll() {
	w.closeOnce.Do(func() { close(w.done) })
	w.mu.Lock()
	all := make([]*clientSession, 0, len(w.sessions))
	for _, s := range w.sessions {
		all = append(all, s)
	}
	w.mu.Unlock()
	for _, s := range all {
		w.finish(s)
	}
	w.link.Close()
}

// -------- 开子流(用户流量)--------

// OpenStream 开一条承载用户流量的子流,返回一个到目标的 net.Conn。
// 先发一个空 New 帧向 Bridge 注册目标(Bridge 据此拨本地目标),后续 Write 走 Keep 帧。
func (w *ClientWorker) OpenStream(network TargetNetwork, addr Address, port uint16) (net.Conn, error) {
	id := w.allocID()
	bp := newBufPipe(sessionBufLimit)
	cs := &clientSession{id: id, inW: bp, closed: make(chan struct{})}
	w.addSession(cs)

	m := &FrameMetadata{SessionID: id, Status: StatusNew, Network: network, Address: addr, Port: port}
	if err := w.writeFrame(m, nil); err != nil {
		w.removeSession(id)
		bp.Close()
		return nil, err
	}
	return &clientConn{w: w, id: id, cs: cs, pr: bp}, nil
}

// clientConn —— OpenStream 返回的子流,实现 net.Conn。
// Read 从解复用管道取回程数据;Write 封成 Keep 帧发出;Close 发 End。
type clientConn struct {
	w    *ClientWorker
	id   uint16
	cs   *clientSession
	pr   *bufPipe
	once sync.Once
}

func (c *clientConn) Read(p []byte) (int, error)  { return c.pr.Read(p) }

func (c *clientConn) Write(p []byte) (int, error) {
	if err := c.w.writeData(c.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *clientConn) Close() error {
	c.once.Do(func() {
		c.w.writeEnd(c.id, false)
		c.w.finish(c.cs)
	})
	return nil
}

func (c *clientConn) LocalAddr() net.Addr                { return muxAddr{} }
func (c *clientConn) RemoteAddr() net.Addr               { return muxAddr{} }
func (c *clientConn) SetDeadline(t time.Time) error      { return nil }
func (c *clientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *clientConn) SetWriteDeadline(t time.Time) error { return nil }

type muxAddr struct{}

func (muxAddr) Network() string { return "muxcool" }
func (muxAddr) String() string  { return "muxcool" }

// -------- 控制子流 + 心跳 --------

// StartControl 开控制子流(target 域 "reverse",UDP,port 0)并周期发 Control 心跳,
// 直到 worker 关闭。Bridge 靠此保活(Xray Bridge 有 60s 不活动定时器)。
func (w *ClientWorker) StartControl(interval time.Duration) error {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	id := w.allocID()
	ctlAddr := Address{IsDomain: true, Domain: InternalDomain}
	// 控制子流是 UDP 类型;New 与后续心跳 Keep 均带 network=UDP + 地址(与 Xray 一致)。
	newFrame := &FrameMetadata{SessionID: id, Status: StatusNew, Network: NetworkUDP, Address: ctlAddr, Port: 0}
	if err := w.writeFrame(newFrame, nil); err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		// 建立即发一次首心跳。
		w.sendHeartbeat(id, ctlAddr)
		for {
			select {
			case <-w.done:
				return
			case <-t.C:
				if err := w.sendHeartbeat(id, ctlAddr); err != nil {
					return
				}
			}
		}
	}()
	return nil
}

func (w *ClientWorker) sendHeartbeat(id uint16, ctlAddr Address) error {
	// UDP 会话的 Keep 帧带 network=UDP + 地址(frame.go marshalMeta 对 Keep&&UDP 写地址)。
	m := &FrameMetadata{SessionID: id, Status: StatusKeep, Network: NetworkUDP, Address: ctlAddr, Port: 0}
	w.mu.Lock()
	draining := w.draining
	w.mu.Unlock()
	if draining {
		return w.writeFrame(m, controlBytes(true))
	}
	return w.writeFrame(m, controlBytes(false))
}

// controlBytes 生成一条 Control protobuf 心跳。
// ACTIVE:proto3 省略 state=0,只剩 field99 random → `9A 06 <len 1..64> <random>`。
// DRAIN:前置 field1 state=1 → `08 01 9A 06 <len> <random>`。
func controlBytes(drain bool) []byte {
	var lb [1]byte
	rand.Read(lb[:])
	n := int(lb[0])%64 + 1 // 1..64
	buf := make([]byte, 0, 5+n)
	if drain {
		buf = append(buf, 0x08, 0x01) // state = DRAIN
	}
	buf = append(buf, 0x9A, 0x06, byte(n))
	r := make([]byte, n)
	rand.Read(r)
	buf = append(buf, r...)
	return buf
}
