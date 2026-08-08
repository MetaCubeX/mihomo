package provider

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// TestRulesMrsParseExtraNoOOM crafts an .mrs whose "extra" length field is a huge untrusted value
// with no body following it. Before the fix, rulesMrsParse did make([]byte, length) here and a
// crafted length aborts the process with an OOM. After the fix the extra bytes are streamed to
// io.Discard, so a bogus length returns a short-read error instead of allocating.
func TestRulesMrsParseExtraNoOOM(t *testing.T) {
	var body bytes.Buffer
	body.Write(MrsMagicBytes[:])                                  // magic "MRS\x01"
	body.WriteByte(0)                                             // behavior = Domain (0)
	binary.Write(&body, binary.BigEndian, int64(0))              // count
	binary.Write(&body, binary.BigEndian, int64(1)<<40)         // extra length ~1 TiB, no body follows

	var packed bytes.Buffer
	enc, err := zstd.NewWriter(&packed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}

	// Must return an error (short read on the extra field), not OOM the process.
	if _, err := rulesMrsParse(packed.Bytes(), NewDomainStrategy()); err == nil {
		t.Fatal("expected an error for a bogus extra length, got nil")
	}
}
