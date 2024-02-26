//go:build !windows

package power

import "errors"

func NewEventListener(cb func(Type)) (func(), error) {
	return nil, errors.New("not support on this platform")
}
