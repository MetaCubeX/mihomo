package updater

import "testing"

func TestNormalizeGithubReleaseVersion(t *testing.T) {
	tests := map[string]string{
		"v1.19.24":           "1.19.24",
		"V1.19.24":           "1.19.24",
		" 1.19.24 \n":        "1.19.24",
		"v1.19.24-custom":    "1.19.24-custom",
		" V1.19.24-custom\n": "1.19.24-custom",
	}

	for input, expected := range tests {
		if actual := normalizeGithubReleaseVersion(input); actual != expected {
			t.Fatalf("normalizeGithubReleaseVersion(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestSameCoreVersionMatchesCustomForkRelease(t *testing.T) {
	tests := map[string]struct {
		latest  string
		current string
		want    bool
	}{
		"custom current matches upstream tag": {
			latest:  "v1.19.24",
			current: "v1.19.24-custom",
			want:    true,
		},
		"plain current matches normalized tag": {
			latest:  "v1.19.24",
			current: "1.19.24",
			want:    true,
		},
		"newer release does not match custom current": {
			latest:  "v1.19.25",
			current: "v1.19.24-custom",
			want:    false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := sameCoreVersion(tt.latest, tt.current); got != tt.want {
				t.Fatalf("sameCoreVersion(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
			}
		})
	}
}

func TestUpdaterPackageNamesSupportBothReleaseWorkflows(t *testing.T) {
	ext := updaterPackageExtension()
	got := updaterPackageNames("mihomo-linux-amd64-v2", "1.19.24")
	want := []string{
		"mihomo-linux-amd64-v2" + ext,
		"mihomo-linux-amd64-v2-1.19.24" + ext,
		"mihomo-linux-amd64-v2-v1.19.24" + ext,
	}

	if len(got) != len(want) {
		t.Fatalf("package names length = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("package name[%d] = %q, want %q; all=%v", i, got[i], want[i], got)
		}
	}
}

func TestUpdaterPackageNamesDoNotAddVersionWhenUnknown(t *testing.T) {
	ext := updaterPackageExtension()
	got := updaterPackageNames("mihomo-linux-amd64-v2", "")
	want := "mihomo-linux-amd64-v2" + ext

	if len(got) != 1 || got[0] != want {
		t.Fatalf("package names = %v, want [%s]", got, want)
	}
}
