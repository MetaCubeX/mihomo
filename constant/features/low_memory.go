//go:build with_low_memory
package features

func init() {
	TAGS = append(TAGS, "with_low_memory")
}
