package muxcool

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPacketSessionWritesXrayUDPFrames(t *testing.T) {
	owner := newFakeSessionOwner()
	globalID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	packetConn, _ := newPacketSession(context.Background(), owner, 31, "initial.example", 53, globalID)
	t.Cleanup(func() { _ = packetConn.Close() })

	firstAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("8.8.8.8:53"))
	if n, err := packetConn.WriteTo([]byte("first"), firstAddr); err != nil || n != 5 {
		t.Fatalf("first WriteTo = (%d, %v)", n, err)
	}
	first := receiveFrame(t, owner.frames)
	if first.Status != StatusNew || first.Network != NetworkUDP || first.Destination != "initial.example" || first.Port != 53 {
		t.Fatalf("first frame target = %+v", first)
	}
	if first.GlobalID != globalID || string(first.Payload) != "first" {
		t.Fatalf("first frame = %+v", first)
	}

	secondAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2001:db8::1]:5353"))
	if n, err := packetConn.WriteTo([]byte("second"), secondAddr); err != nil || n != 6 {
		t.Fatalf("second WriteTo = (%d, %v)", n, err)
	}
	second := receiveFrame(t, owner.frames)
	if second.Status != StatusKeep || second.Network != NetworkUDP || second.DestinationIP.String() != "2001:db8::1" || second.Port != 5353 {
		t.Fatalf("second frame target = %+v", second)
	}
	if second.GlobalID != [8]byte{} || string(second.Payload) != "second" {
		t.Fatalf("second frame = %+v", second)
	}
}

func TestPacketSessionPreservesDatagramBoundariesAndAddresses(t *testing.T) {
	owner := newFakeSessionOwner()
	packetConn, session := newPacketSession(context.Background(), owner, 32, "initial.example", 53, [8]byte{})
	t.Cleanup(func() { _ = packetConn.Close() })

	if err := session.deliverFrame(Frame{
		SessionID: 32, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
		Destination: "1.1.1.1", Port: 853, Payload: []byte("first-packet"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := session.deliverFrame(Frame{
		SessionID: 32, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
		Destination: "reply.example", Port: 5353, Payload: []byte("two"),
	}); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 5)
	n, addr, err := packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(buffer) || string(buffer) != "first" || addr.String() != "1.1.1.1:853" {
		t.Fatalf("first ReadFrom = (%d, %q, %v)", n, buffer, addr)
	}

	buffer = make([]byte, 16)
	n, addr, err = packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || string(buffer[:n]) != "two" || addr.String() != "reply.example:5353" {
		t.Fatalf("second ReadFrom = (%d, %q, %v)", n, buffer[:n], addr)
	}
}

func TestPacketSessionDeadlineCancellationAndClose(t *testing.T) {
	owner := newFakeSessionOwner()
	ctx, cancel := context.WithCancelCause(context.Background())
	packetConn, _ := newPacketSession(ctx, owner, 33, "cancel.example", 53, [8]byte{})

	if err := packetConn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := packetConn.ReadFrom(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("ReadFrom error = %v, want timeout", err)
	}
	if err := packetConn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := packetConn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := packetConn.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.1.1.1:53"))); !isTimeout(err) {
		t.Fatalf("WriteTo error = %v, want timeout", err)
	}
	if err := packetConn.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	cause := errors.New("packet context stopped")
	cancel(cause)
	select {
	case id := <-owner.removed:
		if id != 33 {
			t.Fatalf("removed ID = %d", id)
		}
	case <-time.After(time.Second):
		t.Fatal("packet session was not removed")
	}
	if _, _, err := packetConn.ReadFrom(make([]byte, 1)); !errors.Is(err, cause) {
		t.Fatalf("ReadFrom error = %v, want %v", err, cause)
	}
	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
	end := receiveFrame(t, owner.frames)
	if end.Status != StatusEnd || end.SessionID != 33 {
		t.Fatalf("End = %+v", end)
	}
	select {
	case extra := <-owner.frames:
		t.Fatalf("unexpected extra frame: %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}
}
