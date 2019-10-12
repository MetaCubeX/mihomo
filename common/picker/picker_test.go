package picker

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func sleepAndSend(ctx context.Context, delay int, input interface{}) func() (interface{}, error) {
	return func() (interface{}, error) {
		timer := time.NewTimer(time.Millisecond * time.Duration(delay))
		select {
		case <-timer.C:
			return input, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func TestPicker_Basic(t *testing.T) {
	picker, ctx := WithContext(context.Background())
	picker.Go(sleepAndSend(ctx, 30, 2))
	picker.Go(sleepAndSend(ctx, 20, 1))

	number := picker.Wait()
	assert.NotNil(t, number)
	assert.Equal(t, number.(int), 1)
}

func TestPicker_Timeout(t *testing.T) {
	picker, ctx := WithTimeout(context.Background(), time.Millisecond*5)
	picker.Go(sleepAndSend(ctx, 20, 1))

	number := picker.Wait()
	assert.Nil(t, number)
}

func TestPicker_WaitWithoutAutoCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*60)
	defer cancel()
	picker := WithoutAutoCancel(ctx)

	trigger := false
	picker.Go(sleepAndSend(ctx, 10, 1))
	picker.Go(func() (interface{}, error) {
		timer := time.NewTimer(time.Millisecond * time.Duration(30))
		select {
		case <-timer.C:
			trigger = true
			return 2, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	elm := picker.WaitWithoutCancel()

	assert.NotNil(t, elm)
	assert.Equal(t, elm.(int), 1)

	elm = picker.Wait()
	assert.True(t, trigger)
	assert.Equal(t, elm.(int), 1)
}
