package sudoku

import "testing"

func TestNormalizeASCIIMode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "prefer_entropy"},
		{"entropy", "prefer_entropy"},
		{"prefer_ascii", "prefer_ascii"},
		{"up_ascii_down_entropy", "up_ascii_down_entropy"},
		{"up_entropy_down_ascii", "up_entropy_down_ascii"},
		{"up_prefer_ascii_down_prefer_entropy", "up_ascii_down_entropy"},
	}

	for _, tt := range tests {
		got, err := NormalizeASCIIMode(tt.in)
		if err != nil {
			t.Fatalf("NormalizeASCIIMode(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizeASCIIMode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	if _, err := NormalizeASCIIMode("up_ascii_down_binary"); err == nil {
		t.Fatalf("expected invalid directional mode to fail")
	}
}

func TestNewTableWithCustomDirectionalOpposite(t *testing.T) {
	table, err := NewTableWithCustom("seed", "up_ascii_down_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatalf("NewTableWithCustom: %v", err)
	}
	if !table.IsASCII {
		t.Fatalf("uplink table should be ascii")
	}
	opposite := table.OppositeDirection()
	if opposite == nil || opposite == table {
		t.Fatalf("expected distinct opposite table")
	}
	if opposite.IsASCII {
		t.Fatalf("downlink table should be entropy/custom")
	}

	symmetric, err := NewTableWithCustom("seed", "prefer_ascii", "xpxvvpvv")
	if err != nil {
		t.Fatalf("NewTableWithCustom symmetric: %v", err)
	}
	if symmetric.OppositeDirection() != symmetric {
		t.Fatalf("symmetric table should point to itself")
	}
}
