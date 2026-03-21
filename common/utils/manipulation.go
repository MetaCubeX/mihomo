package utils

import "github.com/samber/lo"

func EmptyOr[T comparable](v T, def T) T {
	ret, _ := lo.Coalesce(v, def)
	return ret
}
