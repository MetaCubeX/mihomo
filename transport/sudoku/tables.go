package sudoku

import (
	"strings"

	"github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func normalizeCustomPatterns(customTable string, customTables []string) []string {
	patterns := customTables
	if len(patterns) == 0 && strings.TrimSpace(customTable) != "" {
		patterns = []string{customTable}
	}
	if len(patterns) == 0 {
		patterns = []string{""}
	}
	return patterns
}

// NewTablesWithCustomPatterns builds one or more obfuscation tables from x/v/p custom patterns.
// When customTables is non-empty it overrides customTable (matching upstream Sudoku behavior).
//
// Deprecated-ish: prefer NewClientTablesWithCustomPatterns / NewServerTablesWithCustomPatterns.
func NewTablesWithCustomPatterns(key string, tableType string, customTable string, customTables []string) ([]*sudoku.Table, error) {
	patterns := normalizeCustomPatterns(customTable, customTables)
	tables := make([]*sudoku.Table, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		t, err := NewTableWithCustom(key, tableType, pattern)
		if err != nil {
			return nil, err
		}
		tables = append(tables, t)
	}
	return tables, nil
}

func NewClientTablesWithCustomPatterns(key string, tableType string, customTable string, customTables []string) ([]*sudoku.Table, error) {
	return NewTablesWithCustomPatterns(key, tableType, customTable, customTables)
}

// NewServerTablesWithCustomPatterns matches upstream server behavior: when custom table rotation is enabled,
// also accept the default table to avoid forcing clients to update in lockstep.
func NewServerTablesWithCustomPatterns(key string, tableType string, customTable string, customTables []string) ([]*sudoku.Table, error) {
	patterns := normalizeCustomPatterns(customTable, customTables)
	if len(patterns) > 0 && strings.TrimSpace(patterns[0]) != "" {
		patterns = append([]string{""}, patterns...)
	}
	return NewTablesWithCustomPatterns(key, tableType, "", patterns)
}
