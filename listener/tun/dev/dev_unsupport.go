//go:build !linux && !android && !darwin && !windows
// +build !linux,!android,!darwin,!windows

package dev

import (
	"errors"
	"runtime"
)

func OpenTunDevice(tunAddress string, autoRute bool) (TunDevice, error) {
	return nil, errors.New("Unsupported platform " + runtime.GOOS + "/" + runtime.GOARCH)
}

// GetAutoDetectInterface get ethernet interface
func GetAutoDetectInterface() (string, error) {
	return "", nil
}
