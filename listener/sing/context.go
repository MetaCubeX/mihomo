package sing

import (
	"context"
	"golang.org/x/exp/slices"

	"github.com/Dreamacro/clash/adapter/inbound"

	"github.com/sagernet/sing/common/auth"
)

type contextKey string

var ctxKeyAdditions = contextKey("Additions")

func WithAdditions(ctx context.Context, additions ...inbound.Addition) context.Context {
	return context.WithValue(ctx, ctxKeyAdditions, additions)
}

func getAdditions(ctx context.Context) []inbound.Addition {
	if v := ctx.Value(ctxKeyAdditions); v != nil {
		if a, ok := v.([]inbound.Addition); ok {
			return a
		}
	}
	return nil
}

func combineAdditions(ctx context.Context, additions []inbound.Addition) []inbound.Addition {
	additionsCloned := false
	if ctxAdditions := getAdditions(ctx); len(ctxAdditions) > 0 {
		additions = slices.Clone(additions)
		additionsCloned = true
		additions = append(additions, ctxAdditions...)
	}
	if user, ok := auth.UserFromContext[string](ctx); ok {
		if !additionsCloned {
			additions = slices.Clone(additions)
			additionsCloned = true
		}
		additions = append(additions, inbound.WithInUser(user))
	}
	return additions
}
