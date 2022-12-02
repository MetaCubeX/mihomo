//go:build !linux && !windows
// +build !linux,!windows

package pmtud_fix

const (
	DisablePathMTUDiscovery = true
)
