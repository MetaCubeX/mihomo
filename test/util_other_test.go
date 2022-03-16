//go:build !darwin

package main

import (
	"errors"
	"net"
)

func defaultRouteIP() (net.IP, error) {
	return nil, errors.New("not supported")
}
