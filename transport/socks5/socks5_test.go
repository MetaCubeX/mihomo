package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplyCodeForError(t *testing.T) {
	dialErr := func(errno syscall.Errno) error {
		return fmt.Errorf("proxy connect error: %w", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)})
	}
	for _, tt := range []struct {
		err  error
		code Error
	}{
		{dialErr(syscall.ECONNREFUSED), ErrConnectionRefused},
		{dialErr(syscall.EHOSTUNREACH), ErrHostUnreachable},
		{dialErr(syscall.ENETUNREACH), ErrNetworkUnreachable},
		{dialErr(syscall.EPERM), ErrConnectionNotAllowed},
		{context.DeadlineExceeded, ErrGeneralFailure},
		{errors.New("unknown"), ErrGeneralFailure},
	} {
		assert.Equal(t, byte(tt.code), ReplyCodeForError(tt.err), tt.err.Error())
	}
}
