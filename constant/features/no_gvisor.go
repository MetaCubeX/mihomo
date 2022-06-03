//go:build no_gvisor

package features

func init() {
	TAGS = append(TAGS, "no_gvisor")
}
