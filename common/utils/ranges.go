package utils

import (
	"errors"
	"fmt"
	"strconv"
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

		status := strings.Split(s, "-")
		statusLen := len(status)
		if statusLen > 2 {
			return nil, errIntRanges
		}

		start, err := parseFn(strings.Trim(status[0], "[ ]"))
		if err != nil {
			return nil, errIntRanges
		}

		switch statusLen {
		case 1: // Port range
			ranges = append(ranges, NewRange(T(start), T(start)))
		case 2: // Single port
			end, err := parseFn(strings.Trim(status[1], "[ ]"))
			if err != nil {
				return nil, errIntRanges
			}

			ranges = append(ranges, NewRange(T(start), T(end)))
		}
	}

	return ranges, nil
}

func parseUnsigned[T constraints.Unsigned](s string) (T, error) {
	if val, err := strconv.ParseUint(s, 10, 64); err == nil {
		return T(val), nil
	} else {
		return 0, err
	}
}

func NewUnsignedRanges[T constraints.Unsigned](expected string) (IntRanges[T], error) {
	return newIntRanges(expected, parseUnsigned[T])
}

func NewUnsignedRangesFromList[T constraints.Unsigned](list []string) (IntRanges[T], error) {
	return newIntRangesFromList(list, parseUnsigned[T])
}

func parseSigned[T constraints.Signed](s string) (T, error) {
	if val, err := strconv.ParseInt(s, 10, 64); err == nil {
		return T(val), nil
	} else {
		return 0, err
	}
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
		start := r.Start()
		end := r.End()

		var term string
		if start == end {
			term = strconv.Itoa(int(start))
		} else {
			term = strconv.Itoa(int(start)) + "-" + strconv.Itoa(int(end))
		}

		terms[i] = term
	}

	return strings.Join(terms, "/")
}

func (ranges IntRanges[T]) Range(f func(t T) bool) {
	if len(ranges) == 0 {
		return
	}

	for _, r := range ranges {
		for i := r.Start(); i <= r.End(); i++ {
			if !f(i) {
				return
			}
		}
	}
}
