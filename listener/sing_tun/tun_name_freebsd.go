//go:build freebsd

package sing_tun

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// getTunnelName resolves the interface name for a tun device opened from a raw
// file descriptor. The FreeBSD port creates the tun device by name rather than
// passing a descriptor, so this path is normally unused; we still attempt to
// resolve it via the device's TUNGIFNAME ioctl for completeness.
func getTunnelName(fd int32) (string, error) {
	// TUNGIFNAME = _IOR('t', 89, struct ifreq) on FreeBSD.
	const tunGifName = 0x4020745d
	var ifr [unix.IFNAMSIZ + 16]byte
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(tunGifName),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return "", os.NewSyscallError("TUNGIFNAME", errno)
	}
	n := 0
	for n < len(ifr) && ifr[n] != 0 {
		n++
	}
	if n == 0 {
		return "", os.ErrInvalid
	}
	return string(ifr[:n]), nil
}
