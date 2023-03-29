//go:build no_fake_tcp

package features

func init() {
	TAGS = append(TAGS, "no_fake_tcp")
}
