package sing

import (
	"context"

	"github.com/Dreamacro/clash/adapter/inbound"
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
