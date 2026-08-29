package muxcool

import (
	"io"
	"net"
	"sync"
)

// InternalDomain —— 反向代理控制子流的目标域(Xray app/reverse/reverse.go:15 硬编码)。
// Bridge 靠它把"控制流"从"用户数据流"里区分出来。
const InternalDomain = "reverse"

// Dispatcher —— Bridge 收到用户数据子流后,如何拨到本地目标。
// 由上层(listener/reverse)注入:通常接到 mihomo 的 tunnel/规则,落地到 Bridge 所在内网。
type Dispatcher interface {
	// DialTarget 按 target 拨一条到本地目标的双工连接。
	DialTarget(network TargetNetwork, addr Address, port uint16) (net.Conn, error)
}

// ServerWorker —— 在一条(VLESS-Rvs 隧道解出的)明文流上跑 Mux.cool 服务端。
//
// 角色反转:mihomo 主动拨号建隧道,但在 Mux.cool 里是服务端——被动读 Portal 开来的
// New 帧、把子流落地、回写 Keep/End。永不主动开子流、永不回写控制心跳。
type ServerWorker struct {
	link       io.ReadWriteCloser
	dispatcher Dispatcher
	onControl  func(payload []byte) // 控制子流每个数据帧回调(解 Control 心跳);可 nil

	writeMu  sync.Mutex // 串行化所有帧写(多个子流 goroutine 并发回写)
	mu       sync.Mutex
	sessions map[uint16]*serverSession
}

type serverSession struct {
	id      uint16
	control bool
	udp     bool     // UDP 子流:每帧=一个数据报,直写 conn(不经 bufPipe,保数据报边界)
	conn    net.Conn
	inW     *bufPipe // 仅 TCP:reader loop 把上行数据写这里 → 由 goroutine 拷到 conn
	once    sync.Once
}

// NewServerWorker 构造。onControl 可为 nil(此时控制子流数据被丢弃,仍正常 drain)。
func NewServerWorker(link io.ReadWriteCloser, d Dispatcher, onControl func([]byte)) *ServerWorker {
	return &ServerWorker{
		link:       link,
		dispatcher: d,
		onControl:  onControl,
		sessions:   make(map[uint16]*serverSession),
	}
}

// Run 跑读环,直到 link 出错/关闭。返回时清理所有子流。
func (w *ServerWorker) Run() error {
	defer w.closeAll()
	for {
		m, data, err := ReadFrame(w.link)
		if err != nil {
			return err
		}
		switch m.Status {
		case StatusNew:
			w.handleNew(m, data)
		case StatusKeep:
			w.handleKeep(m, data)
		case StatusEnd:
			w.handleEnd(m)
		case StatusKeepAlive:
			// 纯心跳,丢弃(Xray 的 Writer 从不主动发,收到即忽略)。
		}
	}
}

// -------- 帧写(均加锁)--------

func (w *ServerWorker) writeData(id uint16, data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return WriteData(w.link, id, data)
}

func (w *ServerWorker) writeEnd(id uint16, hasErr bool) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return WriteEnd(w.link, id, hasErr)
}

// writeUDPData 回写一个 UDP 数据报为 Keep 帧(带 network=UDP + 地址,对齐 Xray UDP 帧)。
func (w *ServerWorker) writeUDPData(id uint16, addr Address, port uint16, data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	m := &FrameMetadata{SessionID: id, Status: StatusKeep, Network: NetworkUDP, Address: addr, Port: port, Option: OptionData}
	return WriteFrame(w.link, m, data)
}

// -------- 会话表 --------

func (w *ServerWorker) addSession(s *serverSession) {
	w.mu.Lock()
	w.sessions[s.id] = s
	w.mu.Unlock()
}

func (w *ServerWorker) getSession(id uint16) *serverSession {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sessions[id]
}

func (w *ServerWorker) removeSession(id uint16) {
	w.mu.Lock()
	delete(w.sessions, id)
	w.mu.Unlock()
}

// finish 幂等收尾:从表移除、(可选)发 End、关 conn/pipe。
// 两条路径都可能触发(Portal 发来 End / 本地目标读到 EOF),sync.Once 保证只做一次。
func (w *ServerWorker) finish(s *serverSession, sendEnd bool) {
	s.once.Do(func() {
		w.removeSession(s.id)
		if sendEnd {
			w.writeEnd(s.id, false)
		}
		if s.inW != nil {
			s.inW.Close()
		}
		if s.conn != nil {
			s.conn.Close()
		}
	})
}

func (w *ServerWorker) closeAll() {
	w.mu.Lock()
	all := make([]*serverSession, 0, len(w.sessions))
	for _, s := range w.sessions {
		all = append(all, s)
	}
	w.mu.Unlock()
	for _, s := range all {
		w.finish(s, false)
	}
	w.link.Close()
}

// -------- 帧处理 --------

func (w *ServerWorker) handleNew(m *FrameMetadata, data []byte) {
	// 控制子流:target 域 == "reverse"(UDP, port 0)。不拨号,只消费。
	if m.Address.IsDomain && m.Address.Domain == InternalDomain {
		w.addSession(&serverSession{id: m.SessionID, control: true})
		if len(data) > 0 && w.onControl != nil {
			w.onControl(data)
		}
		return
	}

	conn, err := w.dispatcher.DialTarget(m.Network, m.Address, m.Port)
	if err != nil {
		// 落地失败:回一个带 error 的 End 通知 Portal 关会话。
		w.writeEnd(m.SessionID, true)
		return
	}

	// UDP 子流:数据报语义,不经 bufPipe(会丢边界)——每帧直写 conn、每读一个数据报回一 Keep。
	if m.Network == NetworkUDP {
		s := &serverSession{id: m.SessionID, udp: true, conn: conn}
		w.addSession(s)
		go func() {
			buf := make([]byte, 64*1024)
			for {
				n, er := conn.Read(buf)
				if n > 0 {
					if we := w.writeUDPData(m.SessionID, m.Address, m.Port, buf[:n]); we != nil {
						break
					}
				}
				if er != nil {
					break
				}
			}
			w.finish(s, true)
		}()
		if len(data) > 0 {
			conn.Write(data)
		}
		return
	}

	bp := newBufPipe(sessionBufLimit)
	s := &serverSession{id: m.SessionID, conn: conn, inW: bp}
	w.addSession(s)

	// 上行:mux 收到的数据 → 本地目标。
	go func() {
		io.Copy(conn, bp)
	}()

	// 下行:本地目标响应 → mux(Keep 帧);EOF/出错则收尾并发 End。
	go func() {
		buf := make([]byte, StreamChunkSize)
		for {
			n, er := conn.Read(buf)
			if n > 0 {
				if we := w.writeData(m.SessionID, buf[:n]); we != nil {
					break
				}
			}
			if er != nil {
				break
			}
		}
		w.finish(s, true)
	}()

	// New 帧若带首包(Option&Data),先灌给本地目标。
	if len(data) > 0 {
		bp.Write(data)
	}
}

func (w *ServerWorker) handleKeep(m *FrameMetadata, data []byte) {
	s := w.getSession(m.SessionID)
	if s == nil {
		// 未知会话:回 End 通知对端关闭(对齐 Xray server.go:308-311)。
		w.writeEnd(m.SessionID, false)
		return
	}
	if s.control {
		if len(data) > 0 && w.onControl != nil {
			w.onControl(data)
		}
		return
	}
	if s.udp {
		if len(data) > 0 && s.conn != nil {
			s.conn.Write(data) // 每帧=一个数据报,直写 UDP conn
		}
		return
	}
	if len(data) > 0 && s.inW != nil {
		// 注:io.Pipe 同步写,慢速本地目标会背压阻塞读环(HoL)。
		// MVP 可接受;S5 再引入带缓冲/限额的 pipe(对齐 Xray 的 buf pipe 16KB)。
		s.inW.Write(data)
	}
}

func (w *ServerWorker) handleEnd(m *FrameMetadata) {
	if s := w.getSession(m.SessionID); s != nil {
		w.finish(s, false) // Portal 主动关,不回 End
	}
}
