package outbound

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func newTestWireGuard(t *testing.T, name string, port int) *WireGuard {
	t.Helper()
	option := WireGuardOption{
		Name:       name,
		Ip:         "10.9.0.2",
		PrivateKey: "4F7zVRZpPEAHIEFBcZj4NITwyiXwzHHbRMpRlZr9bnk=",
		UDP:        true,
	}
	option.Server = "127.0.0.1"
	option.Port = port
	option.PublicKey = "rsPXORPczwaVYfkc29uC6p2Vcjh2POFmL+quiQbBezk="
	w, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func initTestWireGuard(t *testing.T, w *WireGuard) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return w.init(ctx)
}

// wireGuardDeviceClosed doesn't wait, because closing the device is synchronous.
func wireGuardDeviceClosed(w *WireGuard) bool {
	select {
	case <-w.device.(interface{ Wait() chan struct{} }).Wait():
		return true
	default:
		return false
	}
}

// listenTestPeer returns a local UDP port that silently absorbs the handshakes.
func listenTestPeer(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestWireGuardTakeOverDevice(t *testing.T) {
	port := listenTestPeer(t)

	// the same proxy parsed by three config reloads
	old := newTestWireGuard(t, "wg", port)
	late := newTestWireGuard(t, "wg", port)
	current := newTestWireGuard(t, "wg", port)

	if err := initTestWireGuard(t, old); err != nil {
		t.Fatal(err)
	}
	if err := initTestWireGuard(t, current); err != nil {
		t.Fatal(err)
	}
	if !wireGuardDeviceClosed(old) {
		t.Fatal("device of the outdated outbound is still running")
	}

	// an outdated outbound started later must not take the device back
	if err := initTestWireGuard(t, late); !errors.Is(err, errWireGuardOutdated) {
		t.Fatalf("expected %v, got %v", errWireGuardOutdated, err)
	}
	if wireGuardDeviceClosed(current) {
		t.Fatal("device of the current outbound was closed")
	}

	_ = current.Close()
	wireGuardDevicesMutex.Lock()
	_, exist := wireGuardDevices[current.deviceKey()]
	wireGuardDevicesMutex.Unlock()
	if exist {
		t.Fatal("closed outbound still holds its device key")
	}
}

func TestWireGuardKeepDeviceOfOtherProxy(t *testing.T) {
	port := listenTestPeer(t)

	// different proxies that share a key are left alone
	a := newTestWireGuard(t, "wg-a", port)
	b := newTestWireGuard(t, "wg-b", port)

	if err := initTestWireGuard(t, a); err != nil {
		t.Fatal(err)
	}
	if err := initTestWireGuard(t, b); err != nil {
		t.Fatal(err)
	}
	if wireGuardDeviceClosed(a) || wireGuardDeviceClosed(b) {
		t.Fatal("device of another proxy was closed")
	}
}
