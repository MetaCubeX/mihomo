package resolver

import (
	"context"

	D "github.com/miekg/dns"
)

var DefaultLocalServer LocalServer

type LocalServer interface {
	ServeMsg(ctx context.Context, msg *D.Msg) (*D.Msg, error)
}

// ServeMsg with a dns.Msg, return resolve dns.Msg
func ServeMsg(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if server := DefaultLocalServer; server != nil {
		return server.ServeMsg(ctx, msg)
	}

	return nil, ErrIPNotFound
}
