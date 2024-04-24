//go:build with_gvisor

package outbound

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestWireGuardGC(t *testing.T) {
	option := WireGuardOption{}
	option.Server = "162.159.192.1"
	option.Port = 2408
	option.PrivateKey = "iOx7749AdqH3IqluG7+0YbGKd0m1mcEXAfGRzpy9rG8="
	option.PublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	option.Ip = "172.16.0.2"
	option.Ipv6 = "2606:4700:110:8d29:be92:3a6a:f4:c437"
	option.Reserved = []uint8{51, 69, 125}
	wg, err := NewWireGuard(option)
	if err != nil {
		t.Error(err)
	}
	closeCh := make(chan struct{})
	wg.closeCh = closeCh
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	err = wg.init(ctx)
	if err != nil {
		t.Error(err)
	}
	// must do a small sleep before test GC
	// because it maybe deadlocks if w.device.Close call too fast after w.device.Start
	time.Sleep(10 * time.Millisecond)
	wg = nil
	runtime.GC()
	select {
	case <-closeCh:
		return
	case <-ctx.Done():
		t.Error("timeout not GC")
	}
}
