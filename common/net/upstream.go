package net

import "net"

type netConn interface {
	NetConn() net.Conn
}

// FindUpstream finds a value in an upstream wrapper chain. If accept rejects a
// matching value, the search continues so an outer wrapper cannot hide a valid
// inner value of the same type.
func FindUpstream[T any](value any, accept func(T) bool) (T, bool) {
	for value != nil {
		if candidate, ok := value.(T); ok && (accept == nil || accept(candidate)) {
			return candidate, true
		}
		switch wrapper := value.(type) {
		case WithUpstream:
			value = wrapper.Upstream()
		case netConn:
			value = wrapper.NetConn()
		default:
			value = nil
		}
	}
	var zero T
	return zero, false
}
