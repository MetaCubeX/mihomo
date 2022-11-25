package core

import (
	"context"
	"github.com/metacubex/quic-go"
	"time"
)

// Handle stream close properly
// Ref: https://github.com/libp2p/go-libp2p-quic-transport/blob/master/stream.go
type wrappedQUICStream struct {
	Stream quic.Stream
}

func (s *wrappedQUICStream) StreamID() quic.StreamID {
	return s.Stream.StreamID()
}

func (s *wrappedQUICStream) Read(p []byte) (n int, err error) {
	return s.Stream.Read(p)
}

func (s *wrappedQUICStream) CancelRead(code quic.StreamErrorCode) {
	s.Stream.CancelRead(code)
}

func (s *wrappedQUICStream) SetReadDeadline(t time.Time) error {
	return s.Stream.SetReadDeadline(t)
}

func (s *wrappedQUICStream) Write(p []byte) (n int, err error) {
	return s.Stream.Write(p)
}

func (s *wrappedQUICStream) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

func (s *wrappedQUICStream) CancelWrite(code quic.StreamErrorCode) {
	s.Stream.CancelWrite(code)
}

func (s *wrappedQUICStream) Context() context.Context {
	return s.Stream.Context()
}

func (s *wrappedQUICStream) SetWriteDeadline(t time.Time) error {
	return s.Stream.SetWriteDeadline(t)
}

func (s *wrappedQUICStream) SetDeadline(t time.Time) error {
	return s.Stream.SetDeadline(t)
}
