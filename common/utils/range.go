package utils

import (
	"golang.org/x/exp/constraints"
	"strconv"
	"strings"
)

type Range[T constraints.Ordered] struct {
	start T
	end   T
}

func NewRange[T constraints.Ordered](start, end T) *Range[T] {
	if start > end {
		return &Range[T]{
			start: end,
			end:   start,
		}
	}

	return &Range[T]{
		start: start,
		end:   end,
	}
}

func (r *Range[T]) Contains(t T) bool {
	return t >= r.start && t <= r.end
}

func (r *Range[T]) LeftContains(t T) bool {
	return t >= r.start && t < r.end
}

func (r *Range[T]) RightContains(t T) bool {
	return t > r.start && t <= r.end
}

func (r *Range[T]) Start() T {
	return r.start
}

func (r *Range[T]) End() T {
	return r.end
}

func NewIntRangeList(ranges []string, errPayload error) ([]Range[uint16], error) {
	var rangeList []Range[uint16]
	for _, p := range ranges {
		if p == "" {
			continue
		}

		endpoints := strings.Split(p, "-")
		endpointsLen := len(endpoints)
		if endpointsLen > 2 {
			return nil, errPayload
		}

		portStart, err := strconv.ParseUint(strings.Trim(endpoints[0], "[ ]"), 10, 16)
		if err != nil {
			return nil, errPayload
		}

		switch endpointsLen {
		case 1:
			rangeList = append(rangeList, *NewRange(uint16(portStart), uint16(portStart)))
		case 2:
			portEnd, err := strconv.ParseUint(strings.Trim(endpoints[1], "[ ]"), 10, 16)
			if err != nil {
				return nil, errPayload
			}

			rangeList = append(rangeList, *NewRange(uint16(portStart), uint16(portEnd)))
		}
	}
	return rangeList, nil
}
