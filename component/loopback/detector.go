package loopback

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/common/callback"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/iface"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
)

var disableLoopBackDetector, _ = strconv.ParseBool(os.Getenv("DISABLE_LOOPBACK_DETECTOR"))

func init() {
	if features.CMFA {
		disableLoopBackDetector = true
	}
}

var ErrReject = errors.New("reject loopback connection")

// DIRECT adapters share the same OS UDP socket namespace. Reference counts
// keep a port registered while any adapter/address-family still owns it.
var udpPorts = struct {
	sync.Mutex
	counts map[uint16]int
}{counts: make(map[uint16]int)}

type Detector struct {
	connMap xsync.Map[netip.AddrPort, struct{}]
}

func NewDetector() *Detector {
	if disableLoopBackDetector {
		return nil
	}
	return &Detector{}
}

func (l *Detector) NewConn(conn C.Conn) C.Conn {
	if l == nil {
		return conn
	}
	metadata := C.Metadata{}
	if metadata.SetRemoteAddr(conn.LocalAddr()) != nil {
		return conn
	}
	connAddr := metadata.AddrPort()
	if !connAddr.IsValid() {
		return conn
	}
	l.connMap.Store(connAddr, struct{}{})
	return callback.NewCloseCallbackConn(conn, func() {
		l.connMap.Delete(connAddr)
	})
}

func (l *Detector) NewPacketConn(conn C.PacketConn) C.PacketConn {
	if l == nil {
		return conn
	}
	metadata := C.Metadata{}
	if metadata.SetRemoteAddr(conn.LocalAddr()) != nil {
		return conn
	}
	connAddr := metadata.AddrPort()
	if !connAddr.IsValid() {
		return conn
	}
	port := connAddr.Port()
	udpPorts.Lock()
	udpPorts.counts[port]++
	udpPorts.Unlock()
	return callback.NewCloseCallbackPacketConn(conn, func() {
		udpPorts.Lock()
		if udpPorts.counts[port]--; udpPorts.counts[port] == 0 {
			delete(udpPorts.counts, port)
		}
		udpPorts.Unlock()
	})
}

// ListenPacket checks again after registering the allocated socket. A port
// chosen by the kernel can collide with the original client's source port
// after that client has closed; checking only before allocation misses it.
func (l *Detector) ListenPacket(metadata *C.Metadata, listen func() (C.PacketConn, error)) (C.PacketConn, error) {
	if l == nil {
		return listen()
	}
	if err := l.CheckPacketConn(metadata); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 4; attempt++ {
		conn, err := listen()
		if err != nil {
			return nil, err
		}
		local := C.Metadata{}
		selfCollision := local.SetRemoteAddr(conn.LocalAddr()) == nil &&
			metadata.SrcPort != 0 && local.DstPort == metadata.SrcPort
		conn = l.NewPacketConn(conn)
		// The own-port invariant must not depend on a cached interface list.
		if err := l.CheckPacketConn(metadata); err == nil && !selfCollision {
			return conn, nil
		}
		_ = conn.Close()
		// A conflict with another existing socket cannot be repaired by
		// repeatedly allocating this connection's socket.
		if err := l.CheckPacketConn(metadata); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: unable to allocate a non-conflicting UDP port", ErrReject)
}

func (l *Detector) CheckConn(metadata *C.Metadata) error {
	if l == nil {
		return nil
	}
	connAddr := metadata.SourceAddrPort()
	if !connAddr.IsValid() {
		return nil
	}
	if _, ok := l.connMap.Load(connAddr); ok {
		return fmt.Errorf("%w to: %s", ErrReject, metadata.RemoteAddress())
	}
	return nil
}

func (l *Detector) CheckPacketConn(metadata *C.Metadata) error {
	if l == nil {
		return nil
	}
	connAddr := metadata.SourceAddrPort()
	if !connAddr.IsValid() {
		return nil
	}

	isLocalIp, err := iface.IsLocalIp(connAddr.Addr())
	if err != nil {
		return err
	}
	if !isLocalIp && !connAddr.Addr().IsLoopback() {
		return nil
	}

	udpPorts.Lock()
	_, ok := udpPorts.counts[connAddr.Port()]
	udpPorts.Unlock()
	if ok {
		return fmt.Errorf("%w to: %s", ErrReject, metadata.RemoteAddress())
	}
	return nil
}
