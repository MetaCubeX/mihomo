//go:build !windows

package packet

import (
	"io"
	"net"
	"strconv"
	"syscall"

	"github.com/Dreamacro/clash/common/pool"
)

type enhanceUDPConn struct {
	*net.UDPConn
	rawConn syscall.RawConn
}

func (c *enhanceUDPConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	if c.rawConn == nil {
		c.rawConn, _ = c.UDPConn.SyscallConn()
	}
	var readErr error
	err = c.rawConn.Read(func(fd uintptr) (done bool) {
		readBuf := pool.Get(pool.UDPBufferSize)
		put = func() {
			_ = pool.Put(readBuf)
		}
		var readFrom syscall.Sockaddr
		var readN int
		readN, _, _, readFrom, readErr = syscall.Recvmsg(int(fd), readBuf, nil, 0)
		if readN > 0 {
			data = readBuf[:readN]
		} else {
			put()
			put = nil
		}
		if readErr == syscall.EAGAIN {
			return false
		}
		if readFrom != nil {
			switch from := readFrom.(type) {
			case *syscall.SockaddrInet4:
				ip := from.Addr // copy from.Addr; ip escapes, so this line allocates 4 bytes
				addr = &net.UDPAddr{IP: ip[:], Port: from.Port}
			case *syscall.SockaddrInet6:
				ip := from.Addr // copy from.Addr; ip escapes, so this line allocates 16 bytes
				addr = &net.UDPAddr{IP: ip[:], Port: from.Port, Zone: strconv.FormatInt(int64(from.ZoneId), 10)}
			}
		}
		if readN == 0 {
			readErr = io.EOF
		}
		return true
	})
	if err != nil {
		return
	}
	if readErr != nil {
		err = readErr
		return
	}
	return
}
