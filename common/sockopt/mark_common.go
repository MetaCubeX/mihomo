package sockopt

import "syscall"

func RawConnMark(rc syscall.RawConn, mark int) (err error) {
	var innerErr error
	err = rc.Control(func(fd uintptr) {
		innerErr = markControl(fd, mark)
	})

	if innerErr != nil {
		err = innerErr
	}
	return
}
