package common

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

type DialFunc func(ctx context.Context, dialer C.Dialer) (transport *quic.Transport, addr net.Addr, err error)

type Client interface {
	DialContextWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn DialFunc) (net.Conn, error)
	ListenPacketWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn DialFunc) (net.PacketConn, error)
	OpenStreams() int64
	DialerRef() C.Dialer
	LastVisited() time.Time
	SetLastVisited(last time.Time)
	Close()
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
