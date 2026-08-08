package muxcool

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
)

// 已知向量:New / TCP / IPv4 1.2.3.4:80 / SID=1 / data="hi"
// 期望线上字节(全 big-endian):
//
//	00 0C                               metaLen=12
//	00 01                               SessionID=1
//	01                                  Status=New
//	01                                  Option=Data
//	01                                  Network=TCP
//	00 50                               Port=80
//	01                                  atyp=IPv4
//	01 02 03 04                         1.2.3.4
//	00 02                               dataLen=2
//	68 69                               "hi"
func TestKnownVector_NewTCPv4(t *testing.T) {
	var buf bytes.Buffer
	m := &FrameMetadata{
		SessionID: 1,
		Status:    StatusNew,
		Network:   NetworkTCP,
		Address:   Address{IP: net.IPv4(1, 2, 3, 4)},
		Port:      80,
	}
	if err := WriteFrame(&buf, m, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	want := "000c00010101010050010102030400026869"
	if got := hex.EncodeToString(buf.Bytes()); got != want {
		t.Fatalf("known vector mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func roundtrip(t *testing.T, m *FrameMetadata, data []byte) (*FrameMetadata, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteFrame(&buf, m, data); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	gm, gd, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("leftover bytes after ReadFrame: %d", buf.Len())
	}
	return gm, gd
}

func TestRoundtrip_NewTCPDomain(t *testing.T) {
	m := &FrameMetadata{
		SessionID: 7,
		Status:    StatusNew,
		Network:   NetworkTCP,
		Address:   Address{IsDomain: true, Domain: "example.com"},
		Port:      443,
	}
	gm, gd := roundtrip(t, m, []byte("hello world"))
	if gm.SessionID != 7 || gm.Status != StatusNew || gm.Network != NetworkTCP {
		t.Fatalf("meta mismatch: %+v", gm)
	}
	if !gm.Address.IsDomain || gm.Address.Domain != "example.com" || gm.Port != 443 {
		t.Fatalf("addr mismatch: %+v port=%d", gm.Address, gm.Port)
	}
	if string(gd) != "hello world" {
		t.Fatalf("data mismatch: %q", gd)
	}
}

func TestRoundtrip_NewUDPv4(t *testing.T) {
	m := &FrameMetadata{
		SessionID: 9,
		Status:    StatusNew,
		Network:   NetworkUDP,
		Address:   Address{IP: net.IPv4(8, 8, 8, 8)},
		Port:      53,
	}
	gm, gd := roundtrip(t, m, nil)
	if gm.Network != NetworkUDP || gm.Port != 53 || !gm.Address.IP.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("udp meta mismatch: %+v", gm)
	}
	if gd != nil {
		t.Fatalf("expected no data, got %q", gd)
	}
}

func TestRoundtrip_KeepData(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteData(&buf, 3, []byte("response-bytes")); err != nil {
		t.Fatal(err)
	}
	gm, gd, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if gm.SessionID != 3 || gm.Status != StatusKeep {
		t.Fatalf("keep meta mismatch: %+v", gm)
	}
	if string(gd) != "response-bytes" {
		t.Fatalf("keep data mismatch: %q", gd)
	}
}

func TestRoundtrip_End(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteEnd(&buf, 42, true); err != nil {
		t.Fatal(err)
	}
	gm, gd, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if gm.SessionID != 42 || gm.Status != StatusEnd || !gm.Option.Has(OptionError) {
		t.Fatalf("end meta mismatch: %+v", gm)
	}
	if gd != nil {
		t.Fatalf("end should carry no data, got %q", gd)
	}
}

// WriteData 对超过 8KB 的 payload 切多帧。
func TestWriteData_Chunks(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), StreamChunkSize+100)
	var buf bytes.Buffer
	if err := WriteData(&buf, 1, payload); err != nil {
		t.Fatal(err)
	}
	var got []byte
	frames := 0
	for buf.Len() > 0 {
		m, d, err := ReadFrame(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if m.Status != StatusKeep {
			t.Fatalf("frame %d status=%v", frames, m.Status)
		}
		got = append(got, d...)
		frames++
	}
	if frames != 2 {
		t.Fatalf("expected 2 chunks, got %d", frames)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reassembled payload mismatch")
	}
}

// 形态 B:New 帧尾部带 source/local 扩展块,Bridge 必须解出 target 并忽略尾部。
func TestDecode_SkipsSourceLocal(t *testing.T) {
	// 手工拼一个 New/TCP/1.2.3.4:80 + 额外 source(TCP 5.6.7.8:1234) + local(TCP 127.0.0.1:0)。
	var meta []byte
	meta = binary.BigEndian.AppendUint16(meta, 11) // SID
	meta = append(meta, byte(StatusNew), 0x00)     // status, option(no data)
	meta = append(meta, byte(NetworkTCP))
	meta = binary.BigEndian.AppendUint16(meta, 80)
	meta = append(meta, atypIPv4, 1, 2, 3, 4)
	// source 块:srcNet=net.Network_TCP-1=0x01, port, atyp, addr
	meta = append(meta, 0x01)
	meta = binary.BigEndian.AppendUint16(meta, 1234)
	meta = append(meta, atypIPv4, 5, 6, 7, 8)
	// local 块
	meta = append(meta, 0x01)
	meta = binary.BigEndian.AppendUint16(meta, 0)
	meta = append(meta, atypIPv4, 127, 0, 0, 1)

	var frame []byte
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(meta)))
	frame = append(frame, meta...)

	gm, gd, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if gm.SessionID != 11 || gm.Network != NetworkTCP || gm.Port != 80 {
		t.Fatalf("target mismatch: %+v port=%d", gm, gm.Port)
	}
	if !gm.Address.IP.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("target ip mismatch: %v", gm.Address.IP)
	}
	if gd != nil {
		t.Fatalf("no data expected, got %q", gd)
	}
}

// 空 New 帧(无数据段,option 无 Data)—— Portal 的 writeFirstPayload 100ms 占位会出现。
func TestRoundtrip_NewNoData(t *testing.T) {
	m := &FrameMetadata{
		SessionID: 2,
		Status:    StatusNew,
		Network:   NetworkTCP,
		Address:   Address{IP: net.IPv4(10, 0, 0, 1)},
		Port:      8080,
	}
	gm, gd := roundtrip(t, m, nil)
	if gm.Option.Has(OptionData) {
		t.Fatal("should not have Data option")
	}
	if gd != nil {
		t.Fatalf("expected nil data, got %q", gd)
	}
}
