package utils

import (
	"fmt"
	"strconv"
	"strings"

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

func (r Range[T]) String() string {
	if r.start == r.end {
		return fmt.Sprintf("%v", r.start)
	}
	return fmt.Sprintf("%v-%v", r.start, r.end)
}

func NewUnsignedRange[T constraints.Unsigned](expected string) (Range[T], error) {
	return newIntRange(expected, parseUnsigned[T])
}

func NewSignedRange[T constraints.Signed](expected string) (Range[T], error) {
	return newIntRange(expected, parseSigned[T])
}

func newIntRange[T constraints.Integer](s string, parseFn func(string) (T, error)) (Range[T], error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return NewRange[T](0, 0), nil
	}
	status := strings.Split(s, "-")
	start, err := parseFn(strings.Trim(status[0], "[ ]"))
	if err != nil {
		return Range[T]{}, fmt.Errorf("invalid range: %s", s)
	}
	switch len(status) {
	case 1: // Port range
		return NewRange(start, start), nil
	case 2: // Single port
		end, err := parseFn(strings.Trim(status[1], "[ ]"))
		if err != nil {
			return Range[T]{}, fmt.Errorf("invalid range: %s", s)
		}
		return NewRange(start, end), nil
	default:
		return Range[T]{}, fmt.Errorf("invalid range: %s", s)
	}
}

func parseUnsigned[T constraints.Unsigned](s string) (T, error) {
	if val, err := strconv.ParseUint(s, 10, 64); err == nil {
		return T(val), nil
	} else {
		return 0, err
	}
}

func parseSigned[T constraints.Signed](s string) (T, error) {
	if val, err := strconv.ParseInt(s, 10, 64); err == nil {
		return T(val), nil
	} else {
		return 0, err
	}
}
