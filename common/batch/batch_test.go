package batch

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBatch(t *testing.T) {
	b, _ := New(context.Background())

	now := time.Now()
	b.Go("foo", func() (any, error) {
		time.Sleep(time.Millisecond * 100)
		return "foo", nil
	})
	b.Go("bar", func() (any, error) {
		time.Sleep(time.Millisecond * 150)
		return "bar", nil
	})
	result, err := b.WaitAndGetResult()

	assert.Nil(t, err)

	duration := time.Since(now)
	assert.Less(t, duration, time.Millisecond*200)
	assert.Equal(t, 2, len(result))

	for k, v := range result {
		assert.NoError(t, v.Err)
		assert.Equal(t, k, v.Value.(string))
	}
}

func TestBatchWithConcurrencyNum(t *testing.T) {
	b, _ := New(
		context.Background(),
		WithConcurrencyNum(3),
	)

	now := time.Now()
	for i := 0; i < 7; i++ {
		idx := i
		b.Go(strconv.Itoa(idx), func() (any, error) {
			time.Sleep(time.Millisecond * 100)
			return strconv.Itoa(idx), nil
		})
	}
	result, _ := b.WaitAndGetResult()
	duration := time.Since(now)
	assert.Greater(t, duration, time.Millisecond*260)
	assert.Equal(t, 7, len(result))

	for k, v := range result {
		assert.NoError(t, v.Err)
		assert.Equal(t, k, v.Value.(string))
	}
}

func TestBatchContext(t *testing.T) {
	b, ctx := New(context.Background())

	b.Go("error", func() (any, error) {
		time.Sleep(time.Millisecond * 100)
		return nil, errors.New("test error")
	})

	b.Go("ctx", func() (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	result, err := b.WaitAndGetResult()

	assert.NotNil(t, err)
	assert.Equal(t, "error", err.Key)

	assert.Equal(t, ctx.Err(), result["ctx"].Err)
}
