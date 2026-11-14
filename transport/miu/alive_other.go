//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package miu

import "net"

// connAlive cannot peek on this platform: every idle lane is assumed alive, and a dead one is caught by
// the replay of the stream that runs into it.
func connAlive(net.Conn) (alive, pending bool) { return true, false }
