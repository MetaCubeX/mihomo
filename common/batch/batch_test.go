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
	b, _ := New[string](context.Background())

	now := time.Now()
	b.Go("foo", func() (string, error) {
		time.Sleep(time.Millisecond * 100)
		return "foo", nil
	})
	b.Go("bar", func() (string, error) {
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
		assert.Equal(t, k, v.Value)
	}
}

func TestBatchWithConcurrencyNum(t *testing.T) {
	b, _ := New[string](
		context.Background(),
		WithConcurrencyNum[string](3),
	)

	now := time.Now()
	for i := 0; i < 7; i++ {
		idx := i
		b.Go(strconv.Itoa(idx), func() (string, error) {
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
		assert.Equal(t, k, v.Value)
	}
}

func TestBatchContext(t *testing.T) {
	b, ctx := New[string](context.Background())

	b.Go("error", func() (string, error) {
		time.Sleep(time.Millisecond * 100)
		return "", errors.New("test error")
	})

	b.Go("ctx", func() (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})

	result, err := b.WaitAndGetResult()

	assert.NotNil(t, err)
	assert.Equal(t, "error", err.Key)

	assert.Equal(t, ctx.Err(), result["ctx"].Err)
}
