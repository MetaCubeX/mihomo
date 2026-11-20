package nowhere

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAuthenticationVectors(t *testing.T) {
	key, err := authKey("secret")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key[:]) != "8de7e08dd22134ac5acc57902658a36b7f6f9d219987ed49b934a7529a4d24c5" {
		t.Fatal("key derivation differs from upstream vector")
	}
	exp := make([]byte, 32)
	var session [16]byte
	for i := range exp {
		exp[i] = byte(i)
	}
	for i := range session {
		session[i] = byte(i)
	}
	for i, want := range []string{"000102030405060708090a0b0c0d0e0f91f3033378b001f0de171717c027be00", "000102030405060708090a0b0c0d0e0f97d0be56bda8a0ee7596775b35efbf68"} {
		carrier := byte(i + 1)
		b := authFrame(key, carrier, exp, session)
		if hex.EncodeToString(b[:]) != want {
			t.Fatal("authentication differs from upstream vector")
		}
		if got, err := readAuth(bytes.NewReader(b[:]), key, carrier, exp); err != nil || got != session {
			t.Fatal(got, err)
		}
		changed := append([]byte(nil), exp...)
		changed[0] ^= 1
		if _, err := readAuth(bytes.NewReader(b[:]), key, carrier, changed); err == nil {
			t.Fatal("accepted replay on different exporter")
		}
		if _, err := readAuth(bytes.NewReader(b[:]), key, 3-carrier, exp); err == nil {
			t.Fatal("accepted replay on different transport")
		}
	}
}

func TestMorphKeyVectors(t *testing.T) {
	k := newMorphKeys("test portal key")
	for key, want := range map[[32]byte]string{k.tcpUp: "90df47db82553ab6b0489ea77a085593475a70c6a61e957ad3ffe0824bd2126a", k.tcpDown: "20bc17a22d08469e60efd4c6bdda76f190c33946599a0797bab2d52007b97e27", k.udpUp: "6837a1f0de5a70baf35de9ba7a77174a665d577bde4000386ddf0e5206b56773", k.udpDown: "798c97f634139bb467919fbbcd705e0eeffe9294164981dc34a72e274d449b79"} {
		if hex.EncodeToString(key[:]) != want {
			t.Fatal("Morph key differs from upstream vector")
		}
	}
}
func TestTargetValidation(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:443", "[::1]:53", "example.com:65535"} {
		b, err := targetBytes(addr)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readTarget(bytes.NewReader(b))
		if err != nil || got != addr {
			t.Fatal(got, err)
		}
	}
	for _, addr := range []string{"host:0", "-bad.example:80", "bad_.example:80", "bad..example:80", "bad.example.:80", "host:65536"} {
		if _, err := targetBytes(addr); err == nil {
			t.Fatalf("accepted %s", addr)
		}
	}
}
func TestHeaderValidation(t *testing.T) {
	for _, b := range [][]byte{{3, 0, 0, 0, 1}, {0, 0, 0, 0, 0}, {0, 128, 0, 0, 1}, {0, 0}} {
		if _, err := readHeader(bytes.NewReader(b)); err == nil {
			t.Fatal("accepted invalid header")
		}
	}
	for up := byte(1); up <= 2; up++ {
		for down := byte(1); down <= 2; down++ {
			h := header{up: up, down: down, id: 123, hops: 7}
			if up != down {
				h.role = open
			}
			got, err := readHeader(bytes.NewReader(h.bytes()))
			if err != nil || got != h || h.validate(up) != nil {
				t.Fatal(got, err)
			}
		}
	}
	if err := readResult(bytes.NewReader([]byte{8})); err == nil {
		t.Fatal("accepted unknown setup result")
	}
}
func FuzzHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := readHeader(bytes.NewReader(b))
		if err == nil {
			got, err := readHeader(bytes.NewReader(h.bytes()))
			if err != nil || got != h {
				t.Fatal("round trip failed")
			}
		}
	})
}
func FuzzTarget(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80})
	f.Fuzz(func(t *testing.T, b []byte) {
		addr, err := readTarget(bytes.NewReader(b))
		if err == nil {
			wire, err := targetBytes(addr)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readTarget(bytes.NewReader(wire))
			if err != nil || got != addr {
				t.Fatal("round trip failed")
			}
		}
	})
}
