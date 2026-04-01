package sudoku

import "testing"

func TestDirectionalCustomTableRotationCollapse(t *testing.T) {
	patterns := []string{"xpxvvpvv", "vxpvxvvp"}

	clientTables, err := NewClientTablesWithCustomPatterns("seed", "up_ascii_down_entropy", "", patterns)
	if err != nil {
		t.Fatalf("client tables: %v", err)
	}
	if len(clientTables) != 2 {
		t.Fatalf("expected ascii-uplink directional rotation to keep 2 tables, got %d", len(clientTables))
	}
	if clientTables[0].Hint() == clientTables[1].Hint() {
		t.Fatalf("expected directional custom tables to carry distinct hints")
	}
	if got, want := clientTables[0].EncodeTable[0][0], clientTables[1].EncodeTable[0][0]; got != want {
		t.Fatalf("expected directional ascii uplink tables to share the same probe layout, got %x want %x", got, want)
	}
	if got, want := clientTables[0].OppositeDirection().EncodeTable[0][0], clientTables[1].OppositeDirection().EncodeTable[0][0]; got == want {
		t.Fatalf("expected directional downlink custom layouts to differ, both got %x", got)
	}

	clientTables, err = NewClientTablesWithCustomPatterns("seed", "up_entropy_down_ascii", "", patterns)
	if err != nil {
		t.Fatalf("client tables entropy uplink: %v", err)
	}
	if len(clientTables) != 2 {
		t.Fatalf("expected entropy-uplink rotation to keep 2 tables, got %d", len(clientTables))
	}

	serverTables, err := NewServerTablesWithCustomPatterns("seed", "up_ascii_down_entropy", "", patterns)
	if err != nil {
		t.Fatalf("server tables: %v", err)
	}
	if len(serverTables) != 2 {
		t.Fatalf("expected ascii-uplink server directional table set to keep 2 tables, got %d", len(serverTables))
	}
	if clientTables, err = NewClientTablesWithCustomPatterns("seed", "up_ascii_down_entropy", patterns[0], nil); err != nil {
		t.Fatalf("client table with single custom pattern: %v", err)
	} else if got, want := serverTables[0].OppositeDirection().EncodeTable[0][0], clientTables[0].OppositeDirection().EncodeTable[0][0]; got != want {
		t.Fatalf("expected server directional downlink table to preserve custom pattern, got %x want %x", got, want)
	}
}
