// Package ntp provide time.Now
//
// DON'T import other package in mihomo to keep minimal internal dependencies
package ntp

import (
	"time"

	"sync/atomic"
)

var _offset atomic.Int64 // [time.Duration]

func SetOffset(offset time.Duration) {
	_offset.Store(int64(offset))
}

func GetOffset() time.Duration {
	return time.Duration(_offset.Load())
}

func Now() time.Time {
	now := time.Now()
	if offset := GetOffset(); offset != 0 {
		now = now.Add(offset)
	}
	return now
}
