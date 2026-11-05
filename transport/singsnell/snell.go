package singsnell

import (
	"context"
	"net"

	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const (
	HeaderVersion   = 0x04
	HeaderPlainLen  = 7
	AEADTagLen      = 16
	HeaderCipherLen = HeaderPlainLen + AEADTagLen
	SaltLen         = 16
	NonceLen        = 12
	MaxPayloadLen   = 0x3fff
)

const RequestVersion = 0x01

const (
	CommandPing      = 0x00
	CommandConnect   = 0x01
	CommandConnectV2 = 0x05
	CommandUDP       = 0x06
)

const (
	ReplyTunnel = 0x00
	ReplyPong   = 0x01
	ReplyError  = 0x02
)

const (
	UDPCommandForward = 0x01
	AddressTypeIPv4   = 0x04
	AddressTypeIPv6   = 0x06
)

var (
	ErrBadVersion         = E.New("snell: bad header version")
	ErrReservedNonZero    = E.New("snell: reserved header octet is non-zero")
	ErrPayloadTooLarge    = E.New("snell: payload length exceeds maximum")
	ErrUnsupportedCommand = E.New("snell: unsupported command")
	ErrUnexpectedReply    = E.New("snell: unexpected reply opcode")
	ErrMissingPSK         = E.New("snell: missing pre-shared key")
	ErrNoUsers            = E.New("snell: no users")
	ErrBadUserKey         = E.New("snell: bad user key")
	ErrDuplicateUserKey   = E.New("snell: duplicate user key")
)

type Method interface {
	DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error)
	DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn
	DialPacketConn(conn net.Conn) (N.NetPacketConn, error)
}

type Handler interface {
	TCPConnectionHandlerEx
	UDPConnectionHandlerEx
}

type Service interface {
	NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose CloseHandlerFunc) error
}

// snell-server v6.0.0b4: FUN_00141bc0: malformed handshakes are torn down abruptly.
type ServerError struct {
	net.Conn
	Source M.Socksaddr
	Cause  error
}

func (e *ServerError) Unwrap() error {
	return e.Cause
}

func (e *ServerError) Error() string {
	return "snell: serve " + e.Source.String() + ": " + e.Cause.Error()
}

type keepSessionKey struct{}

func ContextWithKeepSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*keepSessionKey)(nil), true)
}

func KeepSessionFromContext(ctx context.Context) bool {
	keep, _ := ctx.Value((*keepSessionKey)(nil)).(bool)
	return keep
}
