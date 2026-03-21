//go:build go1.21

package congestion

import "cmp"

func Max[T cmp.Ordered](a, b T) T {
	return max(a, b)
}

func Min[T cmp.Ordered](a, b T) T {
	return min(a, b)
}
