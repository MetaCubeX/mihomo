//go:build no_doq

package features

func init() {
	TAGS = append(TAGS, "no_doq")
}
