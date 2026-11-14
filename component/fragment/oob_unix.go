//go:build unix

package fragment

import "golang.org/x/sys/unix"

const oobSupported = true

// sendOOB sends b with the TCP urgent flag, the last byte of b is the urgent one.
func sendOOB(fd uintptr, b []byte) (int, error) {
	return unix.SendmsgN(int(fd), b, nil, nil, unix.MSG_OOB)
}
