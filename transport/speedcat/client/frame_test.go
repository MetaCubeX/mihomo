// frame_test.go —— stream 帧读写 + UDP 帧体编解码 self-test(对照 Rust frame 读写 + udp.rs decode)。

package client

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// TestFrameRoundTrip WriteFrame → ReadFrame 回环一致(hdr + body 逐字节)。
func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	hdr := wire.FrameHeader{Type: wire.FrameTCPData, Len: 4, Ctr: 0x04030201}
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	if err := WriteFrame(&buf, hdr, body); err != nil {
		t.Fatal(err)
	}
	gotHdr, gotBody, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if gotHdr != hdr {
		t.Fatalf("hdr 不一致: %+v != %+v", gotHdr, hdr)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body 不一致")
	}
}

// TestFrameCleanEOF ReadFrame 读 0 字节(对端干净关闭)→ io.EOF(对照 Rust 干净关闭语义)。
func TestFrameCleanEOF(t *testing.T) {
	_, _, err := ReadFrame(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("应 io.EOF, got %v", err)
	}
}

// TestFrameMidTrunc 帧头读到一半截断 → io.ErrUnexpectedEOF(中段截断,非干净关闭)。
func TestFrameMidTrunc(t *testing.T) {
	_, _, err := ReadFrame(bytes.NewReader([]byte{0x02, 0x00, 0x05})) // 仅 3B(< 7B 头)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("应 io.ErrUnexpectedEOF, got %v", err)
	}
}

// TestUDPAssociateBody UdpAssociate 帧体 [assoc_id:u16][Addr] 编解码 round-trip(域名,易踩坑 #2 atype 映射在 SOCKS5 层)。
func TestUDPAssociateBody(t *testing.T) {
	addr := wire.Addr{Type: wire.AddrTypeDomain, Domain: "example.com", Port: 443}
	body, err := EncodeUDPAssociate(0x1234, addr)
	if err != nil {
		t.Fatal(err)
	}
	aid, got, err := DecodeUDPAssociate(body)
	if err != nil {
		t.Fatal(err)
	}
	if aid != 0x1234 {
		t.Fatalf("assoc_id 0x%04x != 0x1234", aid)
	}
	if got != addr {
		t.Fatalf("addr 不一致: %+v != %+v", got, addr)
	}
}

// TestUDPDataBody UdpData 帧体 [Addr][plen:u16][payload] 编解码 round-trip(IPv4)。
func TestUDPDataBody(t *testing.T) {
	addr := wire.Addr{Type: wire.AddrTypeIPv4, IPv4: [4]byte{8, 8, 8, 8}, Port: 53}
	data := []byte("dns-query-payload")
	body, err := EncodeUDPData(addr, data)
	if err != nil {
		t.Fatal(err)
	}
	gotAddr, gotData, err := DecodeUDPData(body)
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr != addr {
		t.Fatalf("addr 不一致: %+v != %+v", gotAddr, addr)
	}
	if !bytes.Equal(gotData, data) {
		t.Fatalf("data 不一致")
	}
}

// TestUDPDataTrunc UdpData 帧体截断(plen 声明 > 实际)→ ErrUDPBodyTruncated。
func TestUDPDataTrunc(t *testing.T) {
	addr := wire.Addr{Type: wire.AddrTypeIPv4, IPv4: [4]byte{1, 2, 3, 4}, Port: 53}
	ab, _ := addr.MarshalBinary()
	// 手卷 [Addr][plen=10][仅 3B payload] → 截断。
	body := append([]byte{}, ab...)
	body = append(body, 0x00, 0x0a)       // plen=10
	body = append(body, []byte("abc")...) // 仅 3B
	if _, _, err := DecodeUDPData(body); !errors.Is(err, ErrUDPBodyTruncated) {
		t.Fatalf("应 ErrUDPBodyTruncated, got %v", err)
	}
}
