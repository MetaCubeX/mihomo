package openvpn

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
)

func TestTLSAuthClientServerRoundTrip(t *testing.T) {
	client, err := NewTLSAuth(testStaticKey(), "1", AuthSHA1)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(testStaticKey(), "0", AuthSHA1)
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("client hello over openvpn control channel")
	packet, err := client.Wrap(header, 7, 1714567890, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if want := TLSCryptHeaderSize + client.TagSize() + TLSAuthPIDSize + len(plaintext); len(packet) != want {
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
	client, err := NewTLSAuth(testStaticKey(), "1", AuthSHA1)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(testStaticKey(), "0", AuthSHA1)
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

// OpenVPN derives the --tls-auth HMAC from --auth (init.c: tls_auth_key_type.digest
// = options->authname): the tag is digest-sized and the HMAC key is the first
// digest-size bytes of the 64-byte HMAC half of the direction's key slot
// (crypto_openssl.c hmac_ctx_init: key_len = EVP_MD_size(kt)). The wire layout is
// [opcode|session id][tag][packet id|time][payload] with the tag computed over
// packet id|time, then the header, then the payload.
func TestTLSAuthDigestFollowsAuth(t *testing.T) {
	digests := []struct {
		auth    string
		newHash func() hash.Hash
	}{
		{AuthMD5, md5.New},
		{AuthSHA1, sha1.New},
		{AuthSHA256, sha256.New},
		{AuthSHA384, sha512.New384},
		{AuthSHA512, sha512.New},
	}
	staticKey := testStaticKey()
	header := []byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("client hello over openvpn control channel")
	for _, digest := range digests {
		t.Run(digest.auth, func(t *testing.T) {
			client, err := NewTLSAuth(staticKey, "1", digest.auth)
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewTLSAuth(staticKey, "0", digest.auth)
			if err != nil {
				t.Fatal(err)
			}
			size := digest.newHash().Size()
			if client.TagSize() != size {
				t.Fatalf("tag size %d, want digest size %d", client.TagSize(), size)
			}

			packet, err := client.Wrap(header, 7, 1714567890, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if want := TLSCryptHeaderSize + size + TLSAuthPIDSize + len(plaintext); len(packet) != want {
				t.Fatalf("packet length %d, want %d", len(packet), want)
			}

			// key-direction 1 sends with the second key slot; the HMAC key is the
			// first digest-size bytes of that slot's HMAC half.
			hmacKey := staticKey[keySlotSize+64 : keySlotSize+64+size]
			mac := hmac.New(digest.newHash, hmacKey)
			mac.Write(packet[TLSCryptHeaderSize+size : TLSCryptHeaderSize+size+TLSAuthPIDSize])
			mac.Write(header)
			mac.Write(plaintext)
			if tag := packet[TLSCryptHeaderSize : TLSCryptHeaderSize+size]; !hmac.Equal(tag, mac.Sum(nil)) {
				t.Fatalf("tag is not HMAC-%s over packet id, header and payload with the slot's HMAC key", digest.auth)
			}

			if _, _, _, got, err := server.Unwrap(packet); err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("server unwrap: err=%v plaintext=%q", err, got)
			}
		})
	}
}

func TestTLSAuthDigestMismatchIsRejected(t *testing.T) {
	client, err := NewTLSAuth(testStaticKey(), "1", AuthSHA256)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(testStaticKey(), "0", AuthSHA1)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := client.Wrap([]byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8}, 7, 1714567890, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := server.Unwrap(packet); err == nil {
		t.Fatal("a SHA256 tag must not verify under a SHA1 peer")
	}
}

func TestTLSAuthDefaultAndUnsupportedDigest(t *testing.T) {
	// An empty auth follows the config default (SHA256), like the data channel.
	client, err := NewTLSAuth(testStaticKey(), "1", "")
	if err != nil {
		t.Fatal(err)
	}
	if client.TagSize() != sha256.Size {
		t.Fatalf("default tag size %d, want %d", client.TagSize(), sha256.Size)
	}
	if _, err := NewTLSAuth(testStaticKey(), "1", "SHA224"); err == nil {
		t.Fatal("unsupported digest must be refused at construction")
	}
}
