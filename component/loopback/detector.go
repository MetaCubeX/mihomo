package loopback

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"

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

type Detector struct {
	connMap       xsync.Map[netip.AddrPort, struct{}]
	packetConnMap xsync.Map[uint16, struct{}]
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
	l.packetConnMap.Store(port, struct{}{})
	return callback.NewCloseCallbackPacketConn(conn, func() {
		l.packetConnMap.Delete(port)
	})
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
	port, err := l.localPacketSourcePort(metadata)
	if err != nil || port == 0 {
		return err
	}
	if _, ok := l.packetConnMap.Load(port); ok {
		return fmt.Errorf("%w to: %s", ErrReject, metadata.RemoteAddress())
	}
	return nil
}

// CheckPacketConnPort rejects a newly allocated socket that could receive its
// own TUN write-back after the original local client releases its source port.
func (l *Detector) CheckPacketConnPort(metadata *C.Metadata, port uint16) error {
	if l == nil || port == 0 || port != metadata.SrcPort {
		return nil
	}
	sourcePort, err := l.localPacketSourcePort(metadata)
	if err != nil {
		return err
	}
	if sourcePort != 0 {
		return fmt.Errorf("%w to: %s", ErrReject, metadata.RemoteAddress())
	}
	return nil
}

func (l *Detector) localPacketSourcePort(metadata *C.Metadata) (uint16, error) {
	if l == nil {
		return 0, nil
	}
	connAddr := metadata.SourceAddrPort()
	if !connAddr.IsValid() || connAddr.Port() == 0 {
		return 0, nil
	}

	isLocalIp, err := iface.IsLocalIp(connAddr.Addr())
	if err != nil {
		return 0, err
	}
	if !isLocalIp && !connAddr.Addr().IsLoopback() {
		return 0, nil
	}
	return connAddr.Port(), nil
}
