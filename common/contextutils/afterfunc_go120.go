//go:build !go1.21

package contextutils

import (
	"context"
)

func AfterFunc(ctx context.Context, f func()) (stop func() bool) {
	return afterFunc(ctx, f)
}
