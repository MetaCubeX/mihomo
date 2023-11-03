package utils

func MustOK[T any](result T, ok bool) T {
	if ok {
		return result
	}
	panic("operation failed")
}
