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

func NewIntRanges[T constraints.Integer](expected string) (IntRanges[T], error) {
	// example: 200 or 200/302 or 200-400 or 200/204/401-429/501-503
	expected = strings.TrimSpace(expected)
	if len(expected) == 0 || expected == "*" {
		return nil, nil
	}

	list := strings.Split(expected, "/")
	if len(list) > 28 {
		return nil, fmt.Errorf("%w, too many ranges to use, maximum support 28 ranges", errIntRanges)
	}

	return NewIntRangesFromList[T](list)
}

func NewIntRangesFromList[T constraints.Integer](list []string) (IntRanges[T], error) {
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

		start, err := strconv.ParseInt(strings.Trim(status[0], "[ ]"), 10, 64)
		if err != nil {
			return nil, errIntRanges
		}

		switch statusLen {
		case 1:
			ranges = append(ranges, NewRange(T(start), T(start)))
		case 2:
			end, err := strconv.ParseUint(strings.Trim(status[1], "[ ]"), 10, 64)
			if err != nil {
				return nil, errIntRanges
			}

			ranges = append(ranges, NewRange(T(start), T(end)))
		}
	}

	return ranges, nil
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

func (ranges IntRanges[T]) ToString() string {
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
