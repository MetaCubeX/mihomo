package statistic

import (
	"net"
	"time"

	"github.com/Dreamacro/clash/common/buf"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"

	"github.com/gofrs/uuid"
	"go.uber.org/atomic"
)

type tracker interface {
	ID() string
	Close() error
}

type trackerInfo struct {
	UUID          uuid.UUID     `json:"id"`
	Metadata      *C.Metadata   `json:"metadata"`
	UploadTotal   *atomic.Int64 `json:"upload"`
	DownloadTotal *atomic.Int64 `json:"download"`
	Start         time.Time     `json:"start"`
	Chain         C.Chain       `json:"chains"`
	Rule          string        `json:"rule"`
	RulePayload   string        `json:"rulePayload"`
}

type tcpTracker struct {
	C.Conn `json:"-"`
	*trackerInfo
	manager        *Manager
	extendedReader N.ExtendedReader
	extendedWriter N.ExtendedWriter
}

func (tt *tcpTracker) ID() string {
	return tt.UUID.String()
}

func (tt *tcpTracker) Read(b []byte) (int, error) {
	n, err := tt.Conn.Read(b)
	download := int64(n)
	tt.manager.PushDownloaded(download)
	tt.DownloadTotal.Add(download)
	return n, err
}

func (tt *tcpTracker) ReadBuffer(buffer *buf.Buffer) (err error) {
	err = tt.extendedReader.ReadBuffer(buffer)
	download := int64(buffer.Len())
	tt.manager.PushDownloaded(download)
	tt.DownloadTotal.Add(download)
	return
}

func (tt *tcpTracker) Write(b []byte) (int, error) {
	n, err := tt.Conn.Write(b)
	upload := int64(n)
	tt.manager.PushUploaded(upload)
	tt.UploadTotal.Add(upload)
	return n, err
}

func (tt *tcpTracker) WriteBuffer(buffer *buf.Buffer) (err error) {
	err = tt.extendedWriter.WriteBuffer(buffer)
	var upload int64
	if err != nil {
		upload = int64(buffer.Len())
	}
	tt.manager.PushUploaded(upload)
	tt.UploadTotal.Add(upload)
	return
}

func (tt *tcpTracker) Close() error {
	tt.manager.Leave(tt)
	return tt.Conn.Close()
}

func (tt *tcpTracker) Upstream() any {
	return tt.Conn
}

func NewTCPTracker(conn C.Conn, manager *Manager, metadata *C.Metadata, rule C.Rule) *tcpTracker {
	uuid, _ := uuid.NewV4()
	if conn != nil {
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			metadata.RemoteDst = tcpAddr.IP.String()
		} else {
			metadata.RemoteDst = conn.RemoteDestination()
		}
	}

	t := &tcpTracker{
		Conn:    conn,
		manager: manager,
		trackerInfo: &trackerInfo{
			UUID:          uuid,
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(0),
			DownloadTotal: atomic.NewInt64(0),
		},
		extendedReader: N.NewExtendedReader(conn),
		extendedWriter: N.NewExtendedWriter(conn),
	}

	if rule != nil {
		t.trackerInfo.Rule = rule.RuleType().String()
		t.trackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(t)
	return t
}

type udpTracker struct {
	C.PacketConn `json:"-"`
	*trackerInfo
	manager *Manager
}

func (ut *udpTracker) ID() string {
	return ut.UUID.String()
}

func (ut *udpTracker) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := ut.PacketConn.ReadFrom(b)
	download := int64(n)
	ut.manager.PushDownloaded(download)
	ut.DownloadTotal.Add(download)
	return n, addr, err
}

func (ut *udpTracker) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := ut.PacketConn.WriteTo(b, addr)
	upload := int64(n)
	ut.manager.PushUploaded(upload)
	ut.UploadTotal.Add(upload)
	return n, err
}

func (ut *udpTracker) Close() error {
	ut.manager.Leave(ut)
	return ut.PacketConn.Close()
}

func NewUDPTracker(conn C.PacketConn, manager *Manager, metadata *C.Metadata, rule C.Rule) *udpTracker {
	uuid, _ := uuid.NewV4()
	metadata.RemoteDst = conn.RemoteDestination()

	ut := &udpTracker{
		PacketConn: conn,
		manager:    manager,
		trackerInfo: &trackerInfo{
			UUID:          uuid,
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(0),
			DownloadTotal: atomic.NewInt64(0),
		},
	}

	if rule != nil {
		ut.trackerInfo.Rule = rule.RuleType().String()
		ut.trackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(ut)
	return ut
}
