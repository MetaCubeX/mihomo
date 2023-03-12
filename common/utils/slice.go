package utils

func Filter[T comparable](tSlice []T, filter func(t T) bool) []T {
	result := make([]T, 0)
	for _, t := range tSlice {
		if filter(t) {
			result = append(result, t)
		}
	}
	return result
}
