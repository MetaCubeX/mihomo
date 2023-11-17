package features

import(
	"golang.org/x/exp/slices"
)

var TAGS = make([]string, 0, 0)

func Contains(feat string) (bool) {
	return slices.Contains(TAGS, feat)
}