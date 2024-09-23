package outbound

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestHysteriaGC(t *testing.T) {
	option := HysteriaOption{}
	option.Server = "127.0.0.1"
	option.Ports = "200,204,401-429,501-503"
	option.Protocol = "udp"
	option.Up = "1Mbps"
	option.Down = "1Mbps"
	option.HopInterval = 30
	option.Obfs = "salamander"
	option.SNI = "example.com"
	option.ALPN = []string{"h3"}
	hy, err := NewHysteria(option)
	if err != nil {
		t.Error(err)
		return
	}
	closeCh := make(chan struct{})
	hy.closeCh = closeCh
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	hy = nil
	runtime.GC()
	select {
	case <-closeCh:
		return
	case <-ctx.Done():
		t.Error("timeout not GC")
	}
}
