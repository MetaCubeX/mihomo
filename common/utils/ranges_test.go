package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMergeRanges(t *testing.T) {
	t.Parallel()
	for _, testRange := range []struct {
		ranges   IntRanges[uint16]
		expected IntRanges[uint16]
	}{
		{
			ranges: IntRanges[uint16]{
				NewRange[uint16](0, 1),
				NewRange[uint16](1, 2),
			},
			expected: IntRanges[uint16]{
				NewRange[uint16](0, 2),
			},
		},
		{
			ranges: IntRanges[uint16]{
				NewRange[uint16](0, 3),
				NewRange[uint16](5, 7),
				NewRange[uint16](8, 9),
				NewRange[uint16](10, 10),
			},
			expected: IntRanges[uint16]{
				NewRange[uint16](0, 3),
				NewRange[uint16](5, 10),
			},
		},
		{
			ranges: IntRanges[uint16]{
				NewRange[uint16](1, 3),
				NewRange[uint16](2, 6),
				NewRange[uint16](8, 10),
				NewRange[uint16](15, 18),
			},
			expected: IntRanges[uint16]{
				NewRange[uint16](1, 6),
				NewRange[uint16](8, 10),
				NewRange[uint16](15, 18),
			},
		},
		{
			ranges: IntRanges[uint16]{
				NewRange[uint16](1, 3),
				NewRange[uint16](2, 7),
				NewRange[uint16](2, 6),
			},
			expected: IntRanges[uint16]{
				NewRange[uint16](1, 7),
			},
		},
		{
			ranges: IntRanges[uint16]{
				NewRange[uint16](1, 3),
				NewRange[uint16](2, 6),
				NewRange[uint16](2, 7),
			},
			expected: IntRanges[uint16]{
				NewRange[uint16](1, 7),
			},
		},
		{
			ranges: IntRanges[uint16]{
				NewRange[uint16](1, 3),
				NewRange[uint16](2, 65535),
				NewRange[uint16](2, 7),
				NewRange[uint16](3, 16),
			},
			expected: IntRanges[uint16]{
				NewRange[uint16](1, 65535),
			},
		},
	} {
		assert.Equal(t, testRange.expected, testRange.ranges.Merge())
	}
}
