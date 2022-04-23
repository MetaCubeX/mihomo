package picker

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func sleepAndSend[T any](ctx context.Context, delay int, input T) func() (T, error) {
	return func() (T, error) {
		timer := time.NewTimer(time.Millisecond * time.Duration(delay))
		select {
		case <-timer.C:
			return input, nil
		case <-ctx.Done():
			return getZero[T](), ctx.Err()
		}
	}
}

func TestPicker_Basic(t *testing.T) {
	picker, ctx := WithContext[int](context.Background())
	picker.Go(sleepAndSend(ctx, 30, 2))
	picker.Go(sleepAndSend(ctx, 20, 1))

	number := picker.Wait()
	assert.NotNil(t, number)
	assert.Equal(t, number, 1)
}

func TestPicker_Timeout(t *testing.T) {
	picker, ctx := WithTimeout[int](context.Background(), time.Millisecond*5)
	picker.Go(sleepAndSend(ctx, 20, 1))

	number := picker.Wait()
	assert.Equal(t, number, getZero[int]())
	assert.NotNil(t, picker.Error())
}

func getZero[T any]() T {
	var result T
	return result
}
