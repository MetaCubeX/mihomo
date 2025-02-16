package util

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/metacubex/mihomo/log"
)

func StartRoutine(ctx context.Context, d time.Duration, f func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorln("[BUG] %v %s", r, string(debug.Stack()))
			}
		}()
		for {
			time.Sleep(d)
			f()
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
}
