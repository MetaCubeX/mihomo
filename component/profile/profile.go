package profile

import (
	"go.uber.org/atomic"
)

var (
	// StoreSelected is a global switch for storing selected proxy to cache
	StoreSelected = atomic.NewBool(true)
)
