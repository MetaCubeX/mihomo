package updater

import (
	"testing"
)

// TestCoreBaseName validates that the release asset base name matches the
// naming used by the release CI (.github/workflows/build.yml). The CI builds
// assets as "mihomo-<goos>-<output>-<version>.gz", where <output> for each
// platform is:
//
//	android: amd64, arm64-v8, armv7, 386 (no GOAMD64/GOARM suffix except arm64)
//	linux:   amd64[-v1|-v2|-v3], arm64, armv5/6/7, mips[-softfloat|hardfloat], 386, ...
//	darwin:  amd64[-v1|-v2|-v3], arm64
//	windows: amd64[-v1|-v2|-v3], arm64, 386
func TestCoreBaseName(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		goarch  string
		goamd64 string
		goarm   string
		gomips  string
		want    string
	}{
		// android platforms
		{"android amd64", "android", "amd64", "v1", "", "", "mihomo-android-amd64"},
		{"android arm64", "android", "arm64", "", "", "", "mihomo-android-arm64-v8"},
		{"android arm", "android", "arm", "", "7", "", "mihomo-android-armv7"},
		{"android 386", "android", "386", "", "", "", "mihomo-android-386"},
		// linux platforms
		{"linux amd64 v1", "linux", "amd64", "v1", "", "", "mihomo-linux-amd64-v1"},
		{"linux amd64 v2", "linux", "amd64", "v2", "", "", "mihomo-linux-amd64-v2"},
		{"linux amd64 v3", "linux", "amd64", "v3", "", "", "mihomo-linux-amd64-v3"},
		{"linux arm64", "linux", "arm64", "", "", "", "mihomo-linux-arm64"},
		{"linux arm v5", "linux", "arm", "", "5", "", "mihomo-linux-armv5"},
		{"linux arm v7", "linux", "arm", "", "7", "", "mihomo-linux-armv7"},
		{"linux mips hardfloat", "linux", "mips", "", "", "hardfloat", "mihomo-linux-mips-hardfloat"},
		{"linux mipsle softfloat", "linux", "mipsle", "", "", "softfloat", "mihomo-linux-mipsle-softfloat"},
		{"linux 386", "linux", "386", "", "", "", "mihomo-linux-386"},
		// darwin platforms
		{"darwin amd64 v1", "darwin", "amd64", "v1", "", "", "mihomo-darwin-amd64-v1"},
		{"darwin arm64", "darwin", "arm64", "", "", "", "mihomo-darwin-arm64"},
		// windows platforms
		{"windows amd64 v3", "windows", "amd64", "v3", "", "", "mihomo-windows-amd64-v3"},
		{"windows arm64", "windows", "arm64", "", "", "", "mihomo-windows-arm64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coreBaseName(tt.goos, tt.goarch, tt.goamd64, tt.goarm, tt.gomips)
			if got != tt.want {
				t.Errorf("coreBaseName(%s, %s, ...) = %q, want %q", tt.goos, tt.goarch, got, tt.want)
			}
		})
	}
}
