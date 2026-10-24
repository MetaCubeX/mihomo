package constant

import (
	"context"
	"net"

	N "github.com/metacubex/mihomo/common/net"

	"github.com/gofrs/uuid/v5"
)

type PlainContext interface {
	ID() uuid.UUID
}

type ConnContext interface {
	PlainContext
	Metadata() *Metadata
	Conn() *N.BufferedConn
}

type PacketConnContext interface {
	PlainContext
	Metadata() *Metadata
	PacketConn() net.PacketConn
}

type udpRemoteDNSDomainKey struct{}

// WithUDPRemoteDNSDomain scopes remote DNS to the domain of a UDP session's first packet.
// An empty domain means the first packet targeted a literal IP.
func WithUDPRemoteDNSDomain(ctx context.Context, domain string) context.Context {
	return context.WithValue(ctx, udpRemoteDNSDomainKey{}, domain)
}

// UDPRemoteDNSDomainFromContext returns the domain and whether a session scope
// was supplied. Unscoped callers, such as DNS dialers, dial a single target.
func UDPRemoteDNSDomainFromContext(ctx context.Context) (string, bool) {
	domain, scoped := ctx.Value(udpRemoteDNSDomainKey{}).(string)
	return domain, scoped
}
