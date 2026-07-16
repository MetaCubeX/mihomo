package xraymux

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
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
		{
			name: "udp-new-domain-1k",
			frame: Frame{
				SessionID:   2,
				Status:      StatusNew,
				Option:      OptionData,
				Network:     NetworkUDP,
				Destination: "dns.example",
				Port:        53,
				GlobalID:    [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
				Payload:     make([]byte, 1024),
			},
		},
		{
			name: "udp-keep-ipv4-1k",
			frame: Frame{
				SessionID:   2,
				Status:      StatusKeep,
				Option:      OptionData,
				Network:     NetworkUDP,
				Destination: "1.1.1.1",
				Port:        53,
				Payload:     make([]byte, 1024),
			},
		},
		{
			name: "udp-keep-netip-1k",
			frame: Frame{
				SessionID:     2,
				Status:        StatusKeep,
				Option:        OptionData,
				Network:       NetworkUDP,
				DestinationIP: netip.MustParseAddr("1.1.1.1"),
				Port:          53,
				Payload:       make([]byte, 1024),
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
	metadataBuffer := make([]byte, MaxMetadataSize)
	b.ReportAllocs()
	b.SetBytes(MaxPayloadSize)
	for i := 0; i < b.N; i++ {
		reader.Reset(raw)
		frame, err := decodeFrame(&reader, metadataBuffer)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkFrame = frame
	}
}

func BenchmarkDecodeUDPFrame(b *testing.B) {
	raw, err := EncodeFrame(Frame{
		SessionID:   2,
		Status:      StatusKeep,
		Option:      OptionData,
		Network:     NetworkUDP,
		Destination: "1.1.1.1",
		Port:        53,
		Payload:     make([]byte, 1024),
	})
	if err != nil {
		b.Fatal(err)
	}

	var reader bytes.Reader
	metadataBuffer := make([]byte, MaxMetadataSize)
	b.ReportAllocs()
	b.SetBytes(1024)
	for i := 0; i < b.N; i++ {
		reader.Reset(raw)
		frame, err := decodeFrame(&reader, metadataBuffer)
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
	buffer  []byte
}

func (o *benchmarkSessionOwner) writeFrame(frame Frame) error {
	encoded, err := encodeFrame(o.buffer, frame)
	if err != nil {
		return err
	}
	o.buffer = encoded[:0]
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

func BenchmarkPacketSessionWriteTo(b *testing.B) {
	owner := &benchmarkSessionOwner{written: make(chan struct{}, 1)}
	session := makePacketSession(owner, 2, "dns.example", 53, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	addr := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	payload := make([]byte, 1024)
	if _, err := session.WriteTo(payload, addr); err != nil {
		b.Fatal(err)
	}
	<-owner.written

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := session.WriteTo(payload, addr); err != nil {
			b.Fatal(err)
		}
		<-owner.written
	}
}

func BenchmarkPacketSessionDeliverReadFrom(b *testing.B) {
	session := makePacketSession(&benchmarkSessionOwner{}, 2, "dns.example", 53, [8]byte{})
	frame := Frame{
		SessionID:   2,
		Status:      StatusKeep,
		Option:      OptionData,
		Network:     NetworkUDP,
		Destination: "1.1.1.1",
		Port:        53,
		Payload:     make([]byte, 1024),
	}
	buffer := make([]byte, len(frame.Payload))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame.Payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := session.deliverFrame(frame); err != nil {
			b.Fatal(err)
		}
		n, _, err := session.ReadFrom(buffer)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkInt = n
	}
}
