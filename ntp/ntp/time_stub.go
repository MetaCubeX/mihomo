//go:build !(windows || linux || darwin)

package ntp

import (
	"os"
	"time"
)

func setSystemTime(nowTime time.Time) error {
	return os.ErrInvalid
}
