package xraymux

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestDecodeFrameReadsXrayGoldenVectors(t *testing.T) {
	tests := []struct {
		name        string
		status      Status
		option      Option
		sessionID   uint16
		network     Network
		destination string
		port        uint16
		payload     string
	}{
		{name: "domain-new-data", status: StatusNew, option: OptionData, sessionID: 1, network: NetworkTCP, destination: "example.com", port: 443, payload: "hi"},
		{name: "domain-new-empty", status: StatusNew, sessionID: 1, network: NetworkTCP, destination: "example.com", port: 443},
		{name: "ipv4-new-empty", status: StatusNew, sessionID: 2, network: NetworkTCP, destination: "1.2.3.4", port: 53},
		{name: "ipv6-new-empty", status: StatusNew, sessionID: 3, network: NetworkTCP, destination: "::1", port: 8080},
		{name: "keep-data", status: StatusKeep, option: OptionData, sessionID: 1, payload: "ok"},
		{name: "end", status: StatusEnd, sessionID: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := hex.DecodeString(referenceFrames[tt.name])
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			got, err := DecodeFrame(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("DecodeFrame: %v", err)
			}
			if got.Status != tt.status || got.Option != tt.option || got.SessionID != tt.sessionID {
				t.Fatalf("header = status %d option %d session %d", got.Status, got.Option, got.SessionID)
			}
			if got.Network != tt.network || got.Destination != tt.destination || got.Port != tt.port {
				t.Fatalf("target = network %d %s:%d", got.Network, got.Destination, got.Port)
			}
			if string(got.Payload) != tt.payload {
				t.Fatalf("payload = %q, want %q", got.Payload, tt.payload)
			}
		})
	}
}

func TestDecodeFrameRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "truncated length", raw: []byte{0}},
		{name: "oversized metadata", raw: []byte{0x02, 0x01}},
		{name: "metadata shorter than header", raw: []byte{0, 3, 0, 1, 1}},
		{name: "unknown status", raw: []byte{0, 4, 0, 1, 9, 0}},
		{name: "unknown option", raw: []byte{0, 4, 0, 1, 2, 0x80}},
		{name: "new missing target", raw: []byte{0, 4, 0, 1, 1, 0}},
		{name: "invalid network", raw: []byte{0, 8, 0, 1, 1, 0, 9, 0, 80, 2}},
		{name: "invalid address type", raw: []byte{0, 8, 0, 1, 1, 0, 1, 0, 80, 9}},
		{name: "truncated domain", raw: []byte{0, 10, 0, 1, 1, 0, 1, 0, 80, 2, 4, 'a'}},
		{name: "missing payload length", raw: []byte{0, 4, 0, 1, 2, 1}},
		{name: "truncated payload", raw: []byte{0, 4, 0, 1, 2, 1, 0, 4, 'a'}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeFrame(bytes.NewReader(tt.raw))
			if err == nil {
				t.Fatal("expected protocol error")
			}
			var protocolErr *ProtocolError
			if !errors.As(err, &protocolErr) {
				t.Fatalf("error type = %T, want *ProtocolError: %v", err, err)
			}
		})
	}
}
