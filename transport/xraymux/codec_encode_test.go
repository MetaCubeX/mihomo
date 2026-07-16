package xraymux

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncodeFrameMatchesXrayGoldenVectors(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name: "domain-new-data",
			frame: Frame{SessionID: 1, Status: StatusNew, Option: OptionData, Network: NetworkTCP,
				Destination: "example.com", Port: 443, Payload: []byte("hi")},
		},
		{
			name: "domain-new-empty",
			frame: Frame{SessionID: 1, Status: StatusNew, Network: NetworkTCP,
				Destination: "example.com", Port: 443},
		},
		{
			name: "ipv4-new-empty",
			frame: Frame{SessionID: 2, Status: StatusNew, Network: NetworkTCP,
				Destination: "1.2.3.4", Port: 53},
		},
		{
			name: "ipv6-new-empty",
			frame: Frame{SessionID: 3, Status: StatusNew, Network: NetworkTCP,
				Destination: "::1", Port: 8080},
		},
		{
			name:  "keep-data",
			frame: Frame{SessionID: 1, Status: StatusKeep, Option: OptionData, Payload: []byte("ok")},
		},
		{
			name:  "end",
			frame: Frame{SessionID: 1, Status: StatusEnd},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeFrame(tt.frame)
			if err != nil {
				t.Fatalf("EncodeFrame: %v", err)
			}
			want, err := hex.DecodeString(referenceFrames[tt.name])
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("frame mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

func TestWriteStreamDataChunksAtEightKiB(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, MaxPayloadSize+17)
	var carrier bytes.Buffer

	if err := writeStreamData(&carrier, 7, "large.example", 8443, true, payload); err != nil {
		t.Fatalf("writeStreamData: %v", err)
	}

	first, err := decodeReferenceFrameFrom(&carrier)
	if err != nil {
		t.Fatalf("decode first frame: %v", err)
	}
	second, err := decodeReferenceFrameFrom(&carrier)
	if err != nil {
		t.Fatalf("decode second frame: %v", err)
	}
	if first.status != byte(StatusNew) || len(first.payload) != MaxPayloadSize {
		t.Fatalf("first frame status=%d payload=%d", first.status, len(first.payload))
	}
	if second.status != byte(StatusKeep) || len(second.payload) != 17 {
		t.Fatalf("second frame status=%d payload=%d", second.status, len(second.payload))
	}
	if carrier.Len() != 0 {
		t.Fatalf("unexpected trailing bytes: %d", carrier.Len())
	}
}

func decodeReferenceFrameFrom(carrier *bytes.Buffer) (referenceFrame, error) {
	if carrier.Len() < 2 {
		return referenceFrame{}, bytes.ErrTooLarge
	}
	metaLen := int(carrier.Bytes()[0])<<8 | int(carrier.Bytes()[1])
	total := 2 + metaLen
	if carrier.Len() < total {
		return referenceFrame{}, bytes.ErrTooLarge
	}
	if carrier.Bytes()[5]&byte(OptionData) != 0 {
		if carrier.Len() < total+2 {
			return referenceFrame{}, bytes.ErrTooLarge
		}
		payloadLen := int(carrier.Bytes()[total])<<8 | int(carrier.Bytes()[total+1])
		total += 2 + payloadLen
	}
	if carrier.Len() < total {
		return referenceFrame{}, bytes.ErrTooLarge
	}
	raw := append([]byte(nil), carrier.Next(total)...)
	return decodeReferenceFrame(raw)
}
