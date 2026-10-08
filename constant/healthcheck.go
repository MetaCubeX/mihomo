package constant

import "context"

type healthCheckContextKey struct{}

var healthCheckDownloadSizeKey healthCheckContextKey

// MaxHealthCheckDownloadSize bounds the per-proxy transfer of a sized probe: 64 MiB
// still resolves a 100 Mbps threshold inside the default 5 s budget.
const MaxHealthCheckDownloadSize = 64 << 20

// ContextWithHealthCheckDownloadSize sets how many response body bytes a health check
// reads before it stops the clock. A non-positive size is a no-op.
func ContextWithHealthCheckDownloadSize(ctx context.Context, size int) context.Context {
	if size <= 0 {
		return ctx
	}
	return context.WithValue(ctx, healthCheckDownloadSizeKey, size)
}

// HealthCheckDownloadSize returns the byte count set by
// ContextWithHealthCheckDownloadSize, or 0 when unset.
func HealthCheckDownloadSize(ctx context.Context) int {
	size, _ := ctx.Value(healthCheckDownloadSizeKey).(int)
	return size
}
