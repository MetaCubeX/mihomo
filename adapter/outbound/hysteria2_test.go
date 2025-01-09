package outbound

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestHysteria2GC(t *testing.T) {
	option := Hysteria2Option{}
	option.Server = "127.0.0.1"
	option.Ports = "200,204,401-429,501-503"
	option.HopInterval = 30
	option.Password = "password"
	option.Obfs = "salamander"
	option.ObfsPassword = "password"
	option.SNI = "example.com"
	option.ALPN = []string{"h3"}
	hy, err := NewHysteria2(option)
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
