package xhttp

import "testing"

func TestDefaultUplinkChunkSize(t *testing.T) {
	config := Config{UplinkDataPlacement: PlacementHeader}

	got, err := config.GetNormalizedUplinkChunkSize()
	if err != nil {
		t.Fatal(err)
	}
	want := Range{Min: 3 * 1024, Max: 4 * 1024}
	if got != want {
		t.Fatalf("expected %v, got %v", want, got)
	}
}
