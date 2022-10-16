package utils

import (
	"io"
	"net"
	"time"
)

const PipeBufferSize = 65535

func Pipe(src, dst io.ReadWriter, count func(int)) error {
	buf := make([]byte, PipeBufferSize)
	for {
		rn, err := src.Read(buf)
		if rn > 0 {
			if count != nil {
				count(rn)
			}
			_, err := dst.Write(buf[:rn])
			if err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}
}

// count: positive numbers for rw1 to rw2, negative numbers for rw2 to re1
func Pipe2Way(rw1, rw2 io.ReadWriter, count func(int)) error {
	errChan := make(chan error, 2)
	go func() {
		var revCount func(int)
		if count != nil {
			revCount = func(i int) {
				count(-i)
			}
		}
		errChan <- Pipe(rw2, rw1, revCount)
	}()
	go func() {
		errChan <- Pipe(rw1, rw2, count)
	}()
	// We only need the first error
	return <-errChan
}

func PipePairWithTimeout(conn net.Conn, stream io.ReadWriteCloser, timeout time.Duration) error {
	errChan := make(chan error, 2)
	// TCP to stream
	go func() {
		buf := make([]byte, PipeBufferSize)
		for {
			if timeout != 0 {
				_ = conn.SetDeadline(time.Now().Add(timeout))
			}
			rn, err := conn.Read(buf)
			if rn > 0 {
				_, err := stream.Write(buf[:rn])
				if err != nil {
					errChan <- err
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	// Stream to TCP
	go func() {
		buf := make([]byte, PipeBufferSize)
		for {
			rn, err := stream.Read(buf)
			if rn > 0 {
				_, err := conn.Write(buf[:rn])
				if err != nil {
					errChan <- err
					return
				}
				if timeout != 0 {
					_ = conn.SetDeadline(time.Now().Add(timeout))
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	return <-errChan
}
