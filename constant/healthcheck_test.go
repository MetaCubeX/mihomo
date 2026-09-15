package constant

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHealthCheckDownloadSize(t *testing.T) {
	assert.Zero(t, HealthCheckDownloadSize(context.Background()))

	ctx := ContextWithHealthCheckDownloadSize(context.Background(), 1048576)
	assert.Equal(t, 1048576, HealthCheckDownloadSize(ctx))

	assert.Zero(t, HealthCheckDownloadSize(ContextWithHealthCheckDownloadSize(context.Background(), 0)))
	assert.Zero(t, HealthCheckDownloadSize(ContextWithHealthCheckDownloadSize(context.Background(), -1)))
}
