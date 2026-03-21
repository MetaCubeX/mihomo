package utils

import (
	"golang.org/x/exp/constraints"
)

type Range[T constraints.Ordered] struct {
	start T
	end   T
}

func NewRange[T constraints.Ordered](start, end T) Range[T] {
	if start > end {
		return Range[T]{
			start: end,
			end:   start,
		}
	}

	return Range[T]{
		start: start,
		end:   end,
	}
}

func (r Range[T]) Contains(t T) bool {
	return t >= r.start && t <= r.end
}

func (r Range[T]) LeftContains(t T) bool {
	return t >= r.start && t < r.end
}

func (r Range[T]) RightContains(t T) bool {
	return t > r.start && t <= r.end
}

func (r Range[T]) Start() T {
	return r.start
}

func (r Range[T]) End() T {
	return r.end
}
