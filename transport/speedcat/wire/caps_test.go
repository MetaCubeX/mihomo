package wire

import "testing"

// 对照 能力位规则:位旗位与 + FEC_RATIO 等值匹配 + reserved 须 0。
func TestCapsBits(t *testing.T) {
	var c Caps
	c |= CapHasDatagram | CapNoInnerAEAD
	if !c.Has(CapHasDatagram) {
		t.Fatal("HAS_DATAGRAM should be set")
	}
	if !c.Has(CapNoInnerAEAD) {
		t.Fatal("NO_INNER_AEAD should be set")
	}
	if c.Has(CapMUX) {
		t.Fatal("MUX should be off")
	}
}

func TestCapsFECRatio(t *testing.T) {
	var c Caps
	c.SetFECRatio(3)
	if c.FECRatio() != 3 {
		t.Fatalf("got %d want 3", c.FECRatio())
	}
	// FEC bit 5-7 = 0b011<<5 = 0x60。
	if c&0x00E0 != 0x60 {
		t.Fatalf("fec bits = %02x, want 0x60", c&0x00E0)
	}
	// 设置 FEC 不应污染位旗(bit 0-4)。
	if c.Has(CapHasDatagram) {
		t.Fatal("fec set leaked into bit0")
	}
}

// Negotiate 位旗取交集:交集 = 双方都置的位。
func TestNegotiateBitwiseAND(t *testing.T) {
	c := CapHasDatagram | CapUDPTunnelOK | CapMUX
	s := CapHasDatagram | CapUDPTunnelOK | CapBrutalCC
	n := Negotiate(c, s)
	want := CapHasDatagram | CapUDPTunnelOK
	if n != want {
		t.Fatalf("got %016b want %016b", n, want)
	}
}

// Negotiate FEC_RATIO 等值匹配(双方相同非零值才生效)。
func TestNegotiateFECEqualMatch(t *testing.T) {
	var c, s Caps
	c.SetFECRatio(2)
	s.SetFECRatio(2)
	if n := Negotiate(c, s); n.FECRatio() != 2 {
		t.Fatalf("fec should match 2, got %d", n.FECRatio())
	}

	var c2, s2 Caps
	c2.SetFECRatio(1)
	s2.SetFECRatio(2)
	if n := Negotiate(c2, s2); n.FECRatio() != 0 {
		t.Fatal("different fec should be off")
	}

	var c3, s3 Caps
	c3.SetFECRatio(0)
	s3.SetFECRatio(3)
	if n := Negotiate(c3, s3); n.FECRatio() != 0 {
		t.Fatal("zero fec should be off")
	}
}

// Negotiate FEC 残留清除(review follow-up,对齐 Rust allowlist 0x011F,caps.rs:93):
// 双方声明**不同非零** FEC 时,协商 FEC 必 off —— 旧实现(denylist 只清 reserved bit 9-15)会留
// (client&server) 的 FEC 位 AND 残留(如 FEC 1&3 → bit5 残留),与 Rust(FEC 位先恒清零再写协商值)
// 分叉,经 DisguiseHSInput 进 MAC → 伪装路密钥分叉。(1,2) 因 AND=0 不暴露,故旧测试漏了这组对。
func TestNegotiateFECResidueCleared(t *testing.T) {
	pairs := [][2]uint8{{1, 3}, {2, 3}, {3, 1}, {3, 2}}
	for _, p := range pairs {
		var c, s Caps
		c.SetFECRatio(p[0])
		s.SetFECRatio(p[1])
		n := Negotiate(c, s)
		if n.FECRatio() != 0 {
			t.Fatalf("FEC(%d,%d):残留未清,got FEC=%d(应 off)", p[0], p[1], n.FECRatio())
		}
		// 整个 FEC 位区(bit 5-7)须全清(防任何残留位)。
		if n&fecRatioMask != 0 {
			t.Fatalf("FEC(%d,%d):FEC 位区有残留 caps=%016b", p[0], p[1], n)
		}
	}
}

// Negotiate reserved 位强制清零(reserved 须 0;防对端乱置 bit 9-15)。
func TestNegotiateReservedCleared(t *testing.T) {
	bad := Caps(0xFE00) // bit 9-15
	if n := Negotiate(bad, bad); n&0xFE00 != 0 {
		t.Fatalf("reserved not cleared: %016b", n)
	}
}

// Valid 报告 reserved 位是否全 0。
func TestCapsValid(t *testing.T) {
	if !Caps(0).Valid() {
		t.Fatal("zero caps should be valid")
	}
	if !CapNoInnerAEAD.Valid() {
		t.Fatal("bit8 NO_INNER_AEAD valid")
	}
	if Caps(0x0200).Valid() {
		t.Fatal("bit9 reserved invalid")
	}
}

// SetNoInnerAEAD / NoInnerAEAD:置/清 bit 8 + 不污染其他位(对照 Rust caps.rs:60-63,39-41)。
func TestCapsNoInnerAEAD(t *testing.T) {
	var c Caps
	c.SetNoInnerAEAD(true)
	if !c.NoInnerAEAD() {
		t.Fatal("set true 后应置位")
	}
	if c != CapNoInnerAEAD {
		t.Fatalf("set true 应只置 bit8,got %016b", c)
	}
	// 叠其他位再清,确认只清 bit 8。
	c |= CapHasDatagram | CapMUX
	c.SetNoInnerAEAD(false)
	if c.NoInnerAEAD() {
		t.Fatal("set false 后应清位")
	}
	if c.Has(CapHasDatagram) == false || c.Has(CapMUX) == false {
		t.Fatal("清 bit8 不应动其他位")
	}
}

// Bytes / FromBytes:2B 大端往返(对照 Rust to_bytes/from_bytes,caps.rs:74-79)。
func TestCapsBytesRoundtrip(t *testing.T) {
	var c Caps
	c |= CapHasDatagram | CapUDPTunnelOK | CapNoInnerAEAD
	c.SetFECRatio(2)
	got := FromBytes(c.Bytes())
	if got != c {
		t.Fatalf("roundtrip 失败:got %016b want %016b", got, c)
	}
	// 大端字节序断言:高字节在前。
	// 高字节(bits 8-15):仅 bit8 NO_INNER_AEAD → 0x01。
	// 低字节(bits 0-7):bit0 HAS_DATAGRAM(0x01)| bit4 UDP_TUNNEL_OK(0x10)| FEC 2<<5(0x40)= 0x51。
	var expect [2]byte
	expect[0] = 0x01
	expect[1] = 0x01 | 0x10 | (2 << 5) // = 0x51
	b := c.Bytes()
	if b != expect {
		t.Fatalf("bytes = %02x %02x, want %02x %02x", b[0], b[1], expect[0], expect[1])
	}
}
