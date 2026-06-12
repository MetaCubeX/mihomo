package openvpn

import (
	"bytes"
	"testing"
)

func TestTLSAuthClientServerRoundTrip(t *testing.T) {
	client, err := NewTLSAuth(testStaticKey(), AuthSHA256, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.signKey) != 32 {
		t.Fatalf("unexpected SHA256 tls-auth signing key length: %d", len(client.signKey))
	}
	server, err := NewTLSAuth(testStaticKey(), AuthSHA256, 1, false)
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("client hello over openvpn control channel")
	packet, err := client.Wrap(header, 7, 1714567890, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if want := TLSCryptHeaderSize + 32 + TLSCryptPIDSize + len(plaintext); len(packet) != want {
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

func TestTLSAuthServerClientRoundTrip(t *testing.T) {
	client, err := NewTLSAuth(testStaticKey(), AuthSHA256, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(testStaticKey(), AuthSHA256, 1, false)
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{0x40, 8, 7, 6, 5, 4, 3, 2, 1}
	plaintext := []byte("server hello over openvpn control channel")
	packet, err := server.Wrap(header, 9, 1714567900, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	_, packetID, unixTime, gotPlaintext, err := client.Unwrap(packet)
	if err != nil {
		t.Fatal(err)
	}
	if packetID != 9 || unixTime != 1714567900 {
		t.Fatalf("unexpected packet id/time: %d/%d", packetID, unixTime)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("unexpected plaintext: %q", gotPlaintext)
	}
}

func TestTLSAuthRejectsTamperedPacket(t *testing.T) {
	client, err := NewTLSAuth(testStaticKey(), AuthSHA256, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(testStaticKey(), AuthSHA256, 1, false)
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
