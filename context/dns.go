package context

import (
	"context"

	"github.com/gofrs/uuid"
	"github.com/miekg/dns"
)

const (
	DNSTypeHost   = "host"
	DNSTypeFakeIP = "fakeip"
	DNSTypeRaw    = "raw"
)

type DNSContext struct {
	context.Context

	id  uuid.UUID
	msg *dns.Msg
	tp  string
}

func NewDNSContext(ctx context.Context, msg *dns.Msg) *DNSContext {
	id, _ := uuid.NewV4()
	return &DNSContext{
		Context: ctx,

		id:  id,
		msg: msg,
	}
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
