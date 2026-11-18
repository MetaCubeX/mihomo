package types

import (
	"bufio"
	"context"
	"errors"
	"net"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/quic-go"
)

var (
	ClientClosed       = errors.New("tuic: client closed")
	TooManyOpenStreams = errors.New("tuic: too many open streams")
)

type DialFunc func(ctx context.Context) (quicConn *quic.Conn, err error)

type Client interface {
	DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error)
	ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error)
	OpenStreams() int64
	LastVisited() time.Time
	SetLastVisited(last time.Time)
	Close()
	// ForceClose closes the QUIC connection now, open streams included, and
	// refuses further dials. Close waits for the open streams to drain; on a
	// session the server has already dropped they drain only by timing out.
	ForceClose(err error)
}

type ServerHandler interface {
	AuthOk() bool
	HandleTimeout()
	HandleStream(conn *N.BufferedConn) (err error)
	HandleMessage(message []byte) (err error)
	HandleUniStream(reader *bufio.Reader) (err error)
}

type UdpRelayMode uint8

const (
	QUIC UdpRelayMode = iota
	NATIVE
)
