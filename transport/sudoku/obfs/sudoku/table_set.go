package sudoku

import "fmt"

// TableSet is a small helper for managing multiple Sudoku tables (e.g. for per-connection rotation).
// It is intentionally decoupled from the tunnel/app layers.
type TableSet struct {
	Tables []*Table
}

// NewTableSet builds one or more tables from key/mode and a list of custom X/P/V patterns.
// If patterns is empty, it builds a single default table (customPattern="").
func NewTableSet(key string, mode string, patterns []string) (*TableSet, error) {
	if len(patterns) == 0 {
		t, err := NewTableWithCustom(key, mode, "")
		if err != nil {
			return nil, err
		}
		return &TableSet{Tables: []*Table{t}}, nil
	}

	tables := make([]*Table, 0, len(patterns))
	for i, pattern := range patterns {
		t, err := NewTableWithCustom(key, mode, pattern)
		if err != nil {
			return nil, fmt.Errorf("build table[%d] (%q): %w", i, pattern, err)
		}
		tables = append(tables, t)
	}
	return &TableSet{Tables: tables}, nil
}

func (ts *TableSet) Candidates() []*Table {
	if ts == nil {
		return nil
	}
	return ts.Tables
}
