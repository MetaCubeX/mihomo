//go:build linux

package process

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestResolveSocketFromNetlinkMessagesRequiresExactSource(t *testing.T) {
	targetIP := netip.MustParseAddr("10.0.0.9")
	response := newInetDiagResponse(unix.AF_INET, netip.MustParseAddr("192.0.2.10"), 42148, 8964, 1234)

	uid, inode, err := resolveSocketFromNetlinkMessages([]netlink.Message{netlinkMessageForResponse(response)}, targetIP, 42148)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got uid=%d inode=%d err=%v", uid, inode, err)
	}
	if uid != 0 || inode != 0 {
		t.Fatalf("expected empty socket info, got uid=%d inode=%d", uid, inode)
	}
}

func TestResolveSocketFromNetlinkMessagesReturnsExactMatch(t *testing.T) {
	targetIP := netip.MustParseAddr("10.0.0.9")
	noise := newInetDiagResponse(unix.AF_INET, netip.MustParseAddr("192.0.2.10"), 42148, 1000, 1111)
	match := newInetDiagResponse(unix.AF_INET, targetIP, 42148, 8964, 1234)

	uid, inode, err := resolveSocketFromNetlinkMessages([]netlink.Message{
		netlinkMessageForResponse(noise),
		netlinkMessageForResponse(match),
	}, targetIP, 42148)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 8964 || inode != 1234 {
		t.Fatalf("expected exact socket info, got uid=%d inode=%d", uid, inode)
	}
}

func newInetDiagResponse(family byte, ip netip.Addr, port uint16, uid, inode uint32) inetDiagResponse {
	response := inetDiagResponse{
		Family: family,
		UID:    uid,
		INode:  inode,
	}
	binary.BigEndian.PutUint16(response.SrcPort[:], port)
	copy(response.Src[:], ip.AsSlice())
	return response
}

func netlinkMessageForResponse(response inetDiagResponse) netlink.Message {
	data := (*(*[inetDiagResponseSize]byte)(unsafe.Pointer(&response)))[:]
	return netlink.Message{Data: append([]byte(nil), data...)}
}
