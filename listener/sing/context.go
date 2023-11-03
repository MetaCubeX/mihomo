package sing

import (
	"context"
	"golang.org/x/exp/slices"

	"github.com/metacubex/mihomo/adapter/inbound"

	"github.com/sagernet/sing/common/auth"
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
