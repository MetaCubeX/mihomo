package openvpn

import (
	"bytes"
	"testing"
)

func TestScrambleObfuscateRoundTrip(t *testing.T) {
	scramble, err := ParseScramble("obfuscate password")
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	wire := cloneBytes(packet)
	scramble.write(wire)
	if bytes.Equal(wire, packet) {
		t.Fatal("expected scrambled packet to differ")
	}
	scramble.read(wire)
	if !bytes.Equal(wire, packet) {
		t.Fatalf("unexpected unscrambled packet: %x", wire)
	}
}

func TestScrambleReverseLeavesFirstByte(t *testing.T) {
	packet := []byte("abcde")
	bufferReverse(packet)
	if got, want := string(packet), "aedcb"; got != want {
		t.Fatalf("unexpected reverse result: got %q, want %q", got, want)
	}
}
