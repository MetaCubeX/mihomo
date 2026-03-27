//go:build go1.21

package contextutils

import "context"

func WithoutCancel(parent context.Context) context.Context {
	return context.WithoutCancel(parent)
}
