package utils

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/exp/constraints"
)

type IntRanges[T constraints.Integer] []Range[T]

var errIntRanges = errors.New("intRanges error")

func newIntRanges[T constraints.Integer](expected string, parseFn func(string) (T, error)) (IntRanges[T], error) {
	// example: 200 or 200/302 or 200-400 or 200/204/401-429/501-503
	expected = strings.TrimSpace(expected)
	if len(expected) == 0 || expected == "*" {
		return nil, nil
	}

	// support: 200,302 or 200,204,401-429,501-503
	expected = strings.ReplaceAll(expected, ",", "/")
	list := strings.Split(expected, "/")
	if len(list) > 28 {
		return nil, fmt.Errorf("%w, too many ranges to use, maximum support 28 ranges", errIntRanges)
	}

	return newIntRangesFromList[T](list, parseFn)
}

func newIntRangesFromList[T constraints.Integer](list []string, parseFn func(string) (T, error)) (IntRanges[T], error) {
	var ranges IntRanges[T]
	for _, s := range list {
		if s == "" {
			continue
		}

		r, err := newIntRange[T](s, parseFn)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}

	return ranges, nil
}

func NewUnsignedRanges[T constraints.Unsigned](expected string) (IntRanges[T], error) {
	return newIntRanges(expected, parseUnsigned[T])
}

func NewUnsignedRangesFromList[T constraints.Unsigned](list []string) (IntRanges[T], error) {
	return newIntRangesFromList(list, parseUnsigned[T])
}

func NewSignedRanges[T constraints.Signed](expected string) (IntRanges[T], error) {
	return newIntRanges(expected, parseSigned[T])
}

func NewSignedRangesFromList[T constraints.Signed](list []string) (IntRanges[T], error) {
	return newIntRangesFromList(list, parseSigned[T])
}

func (ranges IntRanges[T]) Check(status T) bool {
	if len(ranges) == 0 {
		return true
	}

	for _, segment := range ranges {
		if segment.Contains(status) {
			return true
		}
	}

	return false
}

func (ranges IntRanges[T]) String() string {
	if len(ranges) == 0 {
		return "*"
	}

	terms := make([]string, len(ranges))
	for i, r := range ranges {
		terms[i] = r.String()
	}

	return strings.Join(terms, "/")
}

func (ranges IntRanges[T]) Range(f func(t T) bool) {
	if len(ranges) == 0 {
		return
	}

	for _, r := range ranges {
		for i := r.Start(); i <= r.End() && i >= r.Start(); i++ {
			if !f(i) {
				return
			}
			if i+1 < i { // integer overflow
				break
			}
		}
	}
}

func (ranges IntRanges[T]) Merge() (mergedRanges IntRanges[T]) {
	if len(ranges) == 0 {
		return
	}
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].Start() < ranges[j].Start()
	})
	mergedRanges = ranges[:1]
	var rangeIndex int
	for _, r := range ranges[1:] {
		if mergedRanges[rangeIndex].End()+1 > mergedRanges[rangeIndex].End() && // integer overflow
			r.Start() > mergedRanges[rangeIndex].End()+1 {
			mergedRanges = append(mergedRanges, r)
			rangeIndex++
		} else if r.End() > mergedRanges[rangeIndex].End() {
			mergedRanges[rangeIndex].end = r.End()
		}
	}
	return
}
