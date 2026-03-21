package sing

import (
	"context"
	"golang.org/x/exp/slices"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"

	"github.com/metacubex/sing/common/auth"
)

type contextKey string

var ctxKeyAdditions = contextKey("Additions")

func WithAdditions(ctx context.Context, additions ...inbound.Addition) context.Context {
	return context.WithValue(ctx, ctxKeyAdditions, additions)
}

func getAdditions(ctx context.Context) (additions []inbound.Addition) {
	if v := ctx.Value(ctxKeyAdditions); v != nil {
		if a, ok := v.([]inbound.Addition); ok {
			additions = a
		}
	}
	if user, ok := auth.UserFromContext[string](ctx); ok {
		additions = slices.Clone(additions)
		additions = append(additions, inbound.WithInUser(user))
	}
	return
}

var ctxKeyInAddr = contextKey("InAddr")

func WithInAddr(ctx context.Context, inAddr net.Addr) context.Context {
	return context.WithValue(ctx, ctxKeyInAddr, inAddr)
}

func getInAddr(ctx context.Context) net.Addr {
	if v := ctx.Value(ctxKeyInAddr); v != nil {
		if a, ok := v.(net.Addr); ok {
			return a
		}
	}
	return nil
}
