package tunnel

import (
	"net"
	"testing"
)

type testUDPDomainAddr string

func (a testUDPDomainAddr) Network() string {
	return "udp"
}

func (a testUDPDomainAddr) String() string {
	return string(a)
}

func TestShouldWriteBackDomainAddr(t *testing.T) {
	if !shouldWriteBackDomainAddr(testUDPDomainAddr("magic.example.ts.net:5353")) {
		t.Fatal("expected udp domain addr to be written back directly")
	}
	if shouldWriteBackDomainAddr(testUDPDomainAddr("100.64.0.10:5353")) {
		t.Fatal("ip addr should keep the normal UDPAddr path")
	}
}

func TestCanWriteBackDomainAddrRequiresSupport(t *testing.T) {
	addr := testUDPDomainAddr("magic.example.ts.net:5353")
	if canWriteBackDomainAddr(testWriteBack{}, addr) {
		t.Fatal("domain writeback should be disabled for unsupported inbounds")
	}
	if !canWriteBackDomainAddr(testDomainWriteBack{}, addr) {
		t.Fatal("domain writeback should be enabled for supported inbounds")
	}
}

type testWriteBack struct{}

func (testWriteBack) WriteBack(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

type testDomainWriteBack struct {
	testWriteBack
}

func (testDomainWriteBack) SupportDomainWriteBack() bool {
	return true
}
