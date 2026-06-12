package context

import (
	"context"
	"net/netip"

	"github.com/metacubex/mihomo/common/utils"

	"github.com/gofrs/uuid/v5"
)

const (
	DNSTypeHost   = "host"
	DNSTypeFakeIP = "fakeip"
	DNSTypeRaw    = "raw"
)

type DNSContext struct {
	context.Context

	id       uuid.UUID
	tp       string
	sourceIP netip.Addr
}

type sourceIPKey struct{}

func WithSourceIP(ctx context.Context, sourceIP netip.Addr) context.Context {
	if !sourceIP.IsValid() {
		return ctx
	}
	return context.WithValue(ctx, sourceIPKey{}, sourceIP)
}

func NewDNSContext(ctx context.Context) *DNSContext {
	dnsCtx := &DNSContext{
		Context: ctx,

		id: utils.NewUUIDV4(),
	}
	if sourceIP, ok := ctx.Value(sourceIPKey{}).(netip.Addr); ok {
		dnsCtx.sourceIP = sourceIP
	}
	return dnsCtx
}

// ID implement C.PlainContext ID
func (c *DNSContext) ID() uuid.UUID {
	return c.id
}

// SetType set type of response
func (c *DNSContext) SetType(tp string) {
	c.tp = tp
}

// Type return type of response
func (c *DNSContext) Type() string {
	return c.tp
}

func (c *DNSContext) SourceIP() netip.Addr {
	return c.sourceIP
}
