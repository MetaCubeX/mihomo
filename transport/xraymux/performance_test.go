package xraymux

import (
	"bytes"
	"context"
	"io"
	"testing"
)

var (
	benchmarkBytes []byte
	benchmarkFrame Frame
	benchmarkInt   int
)

func BenchmarkEncodeFrame(b *testing.B) {
	benchmarks := []struct {
		name  string
		frame Frame
	}{
		{
			name: "new-domain-8k",
			frame: Frame{
				SessionID:   1,
				Status:      StatusNew,
				Option:      OptionData,
				Network:     NetworkTCP,
				Destination: "example.com",
				Port:        443,
				Payload:     make([]byte, MaxPayloadSize),
			},
		},
		{
			name: "keep-8k",
			frame: Frame{
				SessionID: 1,
				Status:    StatusKeep,
				Option:    OptionData,
				Payload:   make([]byte, MaxPayloadSize),
			},
		},
	}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(benchmark.frame.Payload)))
			for i := 0; i < b.N; i++ {
				encoded, err := EncodeFrame(benchmark.frame)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkBytes = encoded
			}
		})
	}
}

func BenchmarkDecodeFrame(b *testing.B) {
	raw, err := EncodeFrame(Frame{
		SessionID: 1,
		Status:    StatusKeep,
		Option:    OptionData,
		Payload:   make([]byte, MaxPayloadSize),
	})
	if err != nil {
		b.Fatal(err)
	}

	var reader bytes.Reader
	b.ReportAllocs()
	b.SetBytes(MaxPayloadSize)
	for i := 0; i < b.N; i++ {
		reader.Reset(raw)
		frame, err := DecodeFrame(&reader)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkFrame = frame
	}
}

func BenchmarkSessionDeliver(b *testing.B) {
	s := &session{
		downlink: make(chan downlinkMessage, 1),
		done:     make(chan struct{}),
	}
	payload := make([]byte, MaxPayloadSize)

	b.ReportAllocs()
	b.SetBytes(MaxPayloadSize)
	for i := 0; i < b.N; i++ {
		if err := s.deliver(payload); err != nil {
			b.Fatal(err)
		}
		message := <-s.downlink
		benchmarkInt = len(message.payload)
	}
}

func BenchmarkWriteStreamData(b *testing.B) {
	payload := make([]byte, 64*1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if err := writeStreamData(io.Discard, 1, "example.com", 443, true, payload); err != nil {
			b.Fatal(err)
		}
	}
}

type benchmarkSessionOwner struct {
	written chan struct{}
}

func (o *benchmarkSessionOwner) writeFrame(frame Frame) error {
	encoded, err := EncodeFrame(frame)
	if err != nil {
		return err
	}
	benchmarkBytes = encoded
	if frame.Option&OptionData != 0 {
		o.written <- struct{}{}
	}
	return nil
}

func (*benchmarkSessionOwner) removeSession(uint16) {}

func BenchmarkSessionUplinkFrame(b *testing.B) {
	owner := &benchmarkSessionOwner{written: make(chan struct{})}
	conn, session := makeSession(owner, 1, "example.com", 443)
	session.start(context.Background(), 0)
	payload := make([]byte, MaxPayloadSize)
	b.Cleanup(func() { _ = conn.Close() })

	b.ReportAllocs()
	b.SetBytes(MaxPayloadSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
		<-owner.written
	}
}
