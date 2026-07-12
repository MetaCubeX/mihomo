package openvpn

import (
	"bytes"
	"testing"
)

func TestTLSAuthClientServerRoundTrip(t *testing.T) {
	client, err := NewTLSAuth(testStaticKey(), "1")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(testStaticKey(), "0")
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("client hello over openvpn control channel")
	packet, err := client.Wrap(header, 7, 1714567890, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if want := TLSCryptHeaderSize + TLSAuthTagSize + TLSAuthPIDSize + len(plaintext); len(packet) != want {
		t.Fatalf("unexpected tls-auth packet length: got %d, want %d", len(packet), want)
	}

	gotHeader, packetID, unixTime, gotPlaintext, err := server.Unwrap(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHeader, header) {
		t.Fatalf("unexpected header: %x", gotHeader)
	}
	if packetID != 7 || unixTime != 1714567890 {
		t.Fatalf("unexpected packet id/time: %d/%d", packetID, unixTime)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("unexpected plaintext: %q", gotPlaintext)
	}
}

func TestTLSAuthRejectsTamperedPacket(t *testing.T) {
	client, err := NewTLSAuth(testStaticKey(), "1")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(testStaticKey(), "0")
	if err != nil {
		t.Fatal(err)
	}

	packet, err := client.Wrap([]byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8}, 7, 1714567890, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	packet[len(packet)-1] ^= 0xff

	_, _, _, _, err = server.Unwrap(packet)
	if err == nil {
		t.Fatal("expected authentication failure")
	}
}
