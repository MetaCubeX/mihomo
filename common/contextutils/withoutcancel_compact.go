package contextutils

import (
	"context"
	"time"
)

type withoutCancelCtx struct {
	c context.Context
}

func (withoutCancelCtx) Deadline() (deadline time.Time, ok bool) {
	return
}

func (withoutCancelCtx) Done() <-chan struct{} {
	return nil
}

func (withoutCancelCtx) Err() error {
	return nil
}

func (c withoutCancelCtx) Value(key any) any {
	return c.c.Value(key)
}
