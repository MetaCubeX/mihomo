package fragment

import "golang.org/x/sys/windows"

const oobSupported = true

// sendOOB sends b with the TCP urgent flag, the last byte of b is the urgent one.
func sendOOB(fd uintptr, b []byte) (int, error) {
	buf := windows.WSABuf{Len: uint32(len(b)), Buf: &b[0]}
	var sent uint32
	err := windows.WSASend(windows.Handle(fd), &buf, 1, &sent, windows.MSG_OOB, nil, nil)
	return int(sent), err
}
