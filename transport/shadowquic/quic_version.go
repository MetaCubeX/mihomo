package shadowquic

import (
	"fmt"
	"strings"

	"github.com/metacubex/jls-quic-go"
)

func DefaultQUICVersions() []quic.Version {
	return []quic.Version{quic.Version1}
}

func ParseQUICVersions(values []string) ([]quic.Version, error) {
	versions := make([]quic.Version, 0, len(values))
	for _, value := range values {
		version, err := ParseQUICVersion(value)
		if err != nil {
			return nil, err
		}
		if !containsQUICVersion(versions, version) {
			versions = append(versions, version)
		}
	}
	return versions, nil
}

func ParseQUICVersion(value string) (quic.Version, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	switch normalized {
	case "v1", "1", "rfc9000", "rfc-9000":
		return quic.Version1, nil
	case "v2", "2", "rfc9369", "rfc-9369":
		return quic.Version2, nil
	}
	return 0, fmt.Errorf("unsupported QUIC version %q (supported: v1, v2)", value)
}

func containsQUICVersion(versions []quic.Version, version quic.Version) bool {
	for _, v := range versions {
		if v == version {
			return true
		}
	}
	return false
}
