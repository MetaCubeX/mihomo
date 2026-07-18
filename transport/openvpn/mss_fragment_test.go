package openvpn

import (
	"encoding/binary"
	"testing"
)

func buildTCPSynPacket(mss uint16) []byte {
	pkt := make([]byte, 44)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 44)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], []byte{192, 168, 1, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 1})
	binary.BigEndian.PutUint16(pkt[20:22], 12345)
	binary.BigEndian.PutUint16(pkt[22:24], 443)
	binary.BigEndian.PutUint32(pkt[24:28], 1000)
	pkt[32] = 0x60
	pkt[33] = 0x02
	binary.BigEndian.PutUint16(pkt[34:36], 65535)
	pkt[40] = 2
	pkt[41] = 4
	binary.BigEndian.PutUint16(pkt[42:44], mss)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	binary.BigEndian.PutUint16(pkt[36:38], tcpChecksum(pkt[:20], pkt[20:]))
	return pkt
}

func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func tcpChecksum(ip, tcp []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(ip[12:14]))
	sum += uint32(binary.BigEndian.Uint16(ip[14:16]))
	sum += uint32(binary.BigEndian.Uint16(ip[16:18]))
	sum += uint32(binary.BigEndian.Uint16(ip[18:20]))
	sum += uint32(ip[9])
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func TestClampTCPSegmentMSSReduces(t *testing.T) {
	pkt := buildTCPSynPacket(1460)
	clamped := clampTCPSegmentMSS(pkt, 1200)
	got := binary.BigEndian.Uint16(clamped[42:44])
	if got != 1200 {
		t.Fatalf("expected MSS 1200, got %d", got)
	}
}

func TestClampTCPSegmentMSSNoChangeWhenSmaller(t *testing.T) {
	pkt := buildTCPSynPacket(1000)
	clamped := clampTCPSegmentMSS(pkt, 1200)
	got := binary.BigEndian.Uint16(clamped[42:44])
	if got != 1000 {
		t.Fatalf("expected MSS unchanged 1000, got %d", got)
	}
}

func TestClampTCPSegmentMSSZeroDisabled(t *testing.T) {
	pkt := buildTCPSynPacket(1460)
	clamped := clampTCPSegmentMSS(pkt, 0)
	got := binary.BigEndian.Uint16(clamped[42:44])
	if got != 1460 {
		t.Fatalf("expected MSS unchanged 1460, got %d", got)
	}
}

func TestFragmenterNoFragmentWhenSmall(t *testing.T) {
	f := NewFragmenter()
	payload := []byte("hello")
	parts, err := f.Encode(payload, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 {
		t.Fatalf("expected 1 part, got %d", len(parts))
	}
	got, complete, err := f.Decode(parts[0])
	if err != nil || !complete {
		t.Fatalf("decode failed: %v complete=%v", err, complete)
	}
	if string(got) != string(payload) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

func TestFragmenterSplitsAndReassembles(t *testing.T) {
	f := NewFragmenter()
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}
	parts, err := f.Encode(payload, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(parts))
	}
	var reassembled []byte
	for _, part := range parts {
		got, complete, err := f.Decode(part)
		if err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if complete {
			reassembled = got
		}
	}
	if reassembled == nil {
		t.Fatal("no complete reassembly")
	}
	if len(reassembled) != len(payload) {
		t.Fatalf("length mismatch: got %d, want %d", len(reassembled), len(payload))
	}
	for i := range payload {
		if reassembled[i] != payload[i] {
			t.Fatalf("byte %d mismatch: got %d, want %d", i, reassembled[i], payload[i])
		}
	}
}


