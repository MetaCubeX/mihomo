package tunnel

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	C "github.com/metacubex/mihomo/constant"
)

var tcpConnectTimeout = atomic.NewTypedValue(C.DefaultTCPTimeout)

// ValidateTCPConnectTimeout validates a connection budget in milliseconds.
func ValidateTCPConnectTimeout(milliseconds int64) error {
	if milliseconds <= 0 || milliseconds > math.MaxInt64/int64(time.Millisecond) {
		return fmt.Errorf("tcp-connect-timeout must be a positive number of milliseconds fitting in time.Duration")
	}
	return nil
}

// SetTCPConnectTimeout changes the budget for new tunnel TCP connections.
func SetTCPConnectTimeout(milliseconds int64) error {
	if err := ValidateTCPConnectTimeout(milliseconds); err != nil {
		return err
	}
	tcpConnectTimeout.Store(time.Duration(milliseconds) * time.Millisecond)
	return nil
}

func TCPConnectTimeout() time.Duration {
	return tcpConnectTimeout.Load()
}

func tcpConnectContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, TCPConnectTimeout())
}
