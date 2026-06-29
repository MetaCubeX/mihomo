package common

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
)

func parseSlashSeparatedPayload(payload, valueName string, normalize func(string) string) ([]string, error) {
	parts := strings.Split(payload, "/")
	parsed := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("%s couldn't be empty", valueName)
		}
		if normalize != nil {
			part = normalize(part)
		}
		if slices.Contains(parsed, part) {
			continue
		}
		parsed = append(parsed, part)
	}

	return parsed, nil
}
