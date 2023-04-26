//go:build with_gvisor

package features

func init() {
	TAGS = append(TAGS, "with_gvisor")
}
