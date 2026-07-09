package outbound

import (
	"bytes"
	"testing"
)

func TestParseValueRange(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantStart int
		wantEnd   int
	}{
		{"empty defaults to 0-255", "", 0, 255},
		{"simple range", "65-90", 65, 90},
		{"single value collapses", "100", 100, 100},
		{"invalid falls back", "abc", 0, 255},
		{"end over 255 clamped", "10-300", 10, 255},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := parseValueRange(c.input)
			if r.Start() != c.wantStart || r.End() != c.wantEnd {
				t.Errorf("parseValueRange(%q) = {%d,%d}, want {%d,%d}",
					c.input, r.Start(), r.End(), c.wantStart, c.wantEnd)
			}
		})
	}
}

func TestHeaderCustom_Parse(t *testing.T) {
	t.Run("no clients returns nil", func(t *testing.T) {
		cfg, err := parseHeaderCustomSettings(FinalMaskLayerSettings{})
		if err != nil {
			t.Fatal(err)
		}
		if cfg != nil {
			t.Fatalf("expected nil, got %v", cfg)
		}
	})

	t.Run("type=array (default) with []interface{}", func(t *testing.T) {
		// Simulate what the YAML decoder produces for [72, 84, 84, 80].
		cfg, err := parseHeaderCustomSettings(FinalMaskLayerSettings{
			Clients: [][]HeaderCustomPacket{{
				{Packet: []interface{}{int64(72), int64(84), int64(84), int64(80)}},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		got := cfg.groups[0].packets[0].data
		if !bytes.Equal(got, []byte("HTTP")) {
			t.Errorf("array decode mismatch: %q", got)
		}
	})

	t.Run("type=str", func(t *testing.T) {
		cfg, err := parseHeaderCustomSettings(FinalMaskLayerSettings{
			Clients: [][]HeaderCustomPacket{{
				{Type: "str", Packet: "hello"},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if string(cfg.groups[0].packets[0].data) != "hello" {
			t.Errorf("str decode mismatch: %q", cfg.groups[0].packets[0].data)
		}
	})

	t.Run("type=hex", func(t *testing.T) {
		cfg, _ := parseHeaderCustomSettings(FinalMaskLayerSettings{
			Clients: [][]HeaderCustomPacket{{
				{Type: "hex", Packet: "deadbeef"},
			}},
		})
		if !bytes.Equal(cfg.groups[0].packets[0].data, []byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Errorf("hex decode mismatch: % x", cfg.groups[0].packets[0].data)
		}
	})

	t.Run("type=base64", func(t *testing.T) {
		cfg, _ := parseHeaderCustomSettings(FinalMaskLayerSettings{
			Clients: [][]HeaderCustomPacket{{
				{Type: "base64", Packet: "aGVsbG8="},
			}},
		})
		if string(cfg.groups[0].packets[0].data) != "hello" {
			t.Errorf("base64 decode mismatch: %q", cfg.groups[0].packets[0].data)
		}
	})

	t.Run("rand with default value range", func(t *testing.T) {
		cfg, _ := parseHeaderCustomSettings(FinalMaskLayerSettings{
			Clients: [][]HeaderCustomPacket{{
				{Rand: 16},
			}},
		})
		entry := cfg.groups[0].packets[0]
		if entry.randSize != 16 {
			t.Errorf("randSize = %d, want 16", entry.randSize)
		}
		if entry.valRange.Start() != 0 || entry.valRange.End() != 255 {
			t.Errorf("valRange = %v, want {0,255}", entry.valRange)
		}
	})

	t.Run("rand with custom value range", func(t *testing.T) {
		cfg, _ := parseHeaderCustomSettings(FinalMaskLayerSettings{
			Clients: [][]HeaderCustomPacket{{
				{Rand: 16, RandRange: "65-90"},
			}},
		})
		entry := cfg.groups[0].packets[0]
		if entry.valRange.Start() != 65 || entry.valRange.End() != 90 {
			t.Errorf("valRange = %v, want {65,90}", entry.valRange)
		}
	})

	t.Run("rand and packet mutually exclusive", func(t *testing.T) {
		_, err := parseHeaderCustomSettings(FinalMaskLayerSettings{
			Clients: [][]HeaderCustomPacket{{
				{Rand: 5, Packet: "x"},
			}},
		})
		if err == nil {
			t.Fatal("expected error for rand + packet")
		}
	})

	t.Run("multiple clients produce multiple groups", func(t *testing.T) {
		cfg, _ := parseHeaderCustomSettings(FinalMaskLayerSettings{
			Clients: [][]HeaderCustomPacket{
				{{Packet: "a"}},
				{{Packet: "b"}},
				{{Packet: "c"}},
			},
		})
		if len(cfg.groups) != 3 {
			t.Errorf("got %d groups, want 3", len(cfg.groups))
		}
	})
}

func TestHeaderCustomEntry_Bytes(t *testing.T) {
	t.Run("fixed data returned as-is", func(t *testing.T) {
		e := headerCustomEntry{data: []byte("xyz")}
		got, err := e.bytes()
		if err != nil || string(got) != "xyz" {
			t.Errorf("got %q err=%v", got, err)
		}
	})

	t.Run("default value range produces 8 random bytes", func(t *testing.T) {
		e := headerCustomEntry{randSize: 8, valRange: rangeOf(0, 255)}
		got, err := e.bytes()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 8 {
			t.Errorf("got %d bytes, want 8", len(got))
		}
	})

	t.Run("constrained value range stays in range", func(t *testing.T) {
		e := headerCustomEntry{randSize: 64, valRange: rangeOf(65, 90)}
		got, err := e.bytes()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 64 {
			t.Fatalf("got %d bytes, want 64", len(got))
		}
		for i, b := range got {
			if b < 65 || b > 90 {
				t.Fatalf("byte %d = %d, want in [65,90]", i, b)
			}
		}
	})

	t.Run("fresh randomness across calls", func(t *testing.T) {
		e := headerCustomEntry{randSize: 32, valRange: rangeOf(0, 255)}
		a, _ := e.bytes()
		b, _ := e.bytes()
		if bytes.Equal(a, b) {
			t.Errorf("expected different random bytes across calls")
		}
	})
}

func TestHeaderCustomConn_InjectsOnFirstWriteOnly(t *testing.T) {
	cfg := &headerCustomSettings{
		groups: []headerCustomGroup{
			{packets: []headerCustomEntry{
				{data: []byte("HDR-A")},
				{data: []byte("HDR-B")},
			}},
		},
	}
	rc := newRecordConn()
	conn := newHeaderCustomConn(rc, cfg)

	if _, err := conn.Write([]byte("PAYLOAD")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("MORE")); err != nil {
		t.Fatal(err)
	}

	want := [][]byte{
		[]byte("HDR-A"),
		[]byte("HDR-B"),
		[]byte("PAYLOAD"),
		[]byte("MORE"),
	}
	if len(rc.writes) != len(want) {
		t.Fatalf("got %d writes, want %d", len(rc.writes), len(want))
	}
	for i := range want {
		if string(rc.writes[i]) != string(want[i]) {
			t.Errorf("write[%d] = %q, want %q", i, rc.writes[i], want[i])
		}
	}
}

func TestHeaderCustomConn_RandomGroupSelectedPerConnection(t *testing.T) {
	// Two distinguishable client profiles — each connection must inject
	// exactly one profile's bytes (never both).
	cfg := &headerCustomSettings{
		groups: []headerCustomGroup{
			{packets: []headerCustomEntry{{data: []byte("PROFILE-A")}}},
			{packets: []headerCustomEntry{{data: []byte("PROFILE-B")}}},
		},
	}
	seenA, seenB := false, false
	for i := 0; i < 50; i++ {
		rc := newRecordConn()
		conn := newHeaderCustomConn(rc, cfg)
		if _, err := conn.Write([]byte("X")); err != nil {
			t.Fatal(err)
		}
		if len(rc.writes) != 2 {
			t.Fatalf("iter %d: got %d writes, want 2", i, len(rc.writes))
		}
		switch string(rc.writes[0]) {
		case "PROFILE-A":
			seenA = true
		case "PROFILE-B":
			seenB = true
		default:
			t.Errorf("iter %d: unexpected injected bytes %q", i, rc.writes[0])
		}
		if string(rc.writes[1]) != "X" {
			t.Errorf("iter %d: user payload lost", i)
		}
	}
	if !seenA || !seenB {
		t.Errorf("random selection not diverse: seenA=%v seenB=%v", seenA, seenB)
	}
}

func TestHeaderCustomConn_RandBytesInjected(t *testing.T) {
	cfg := &headerCustomSettings{
		groups: []headerCustomGroup{
			{packets: []headerCustomEntry{
				{randSize: 10, valRange: rangeOf(0, 255)},
			}},
		},
	}
	rc := newRecordConn()
	conn := newHeaderCustomConn(rc, cfg)

	if _, err := conn.Write([]byte("USER")); err != nil {
		t.Fatal(err)
	}
	if len(rc.writes) != 2 {
		t.Fatalf("got %d writes, want 2", len(rc.writes))
	}
	if len(rc.writes[0]) != 10 {
		t.Errorf("rand write len = %d, want 10", len(rc.writes[0]))
	}
	if string(rc.writes[1]) != "USER" {
		t.Errorf("user payload mismatch: got %q", rc.writes[1])
	}
}
