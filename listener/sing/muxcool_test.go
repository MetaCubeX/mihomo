package sing

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/muxcool"

	vmess "github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"
)

func TestListenerHandlerCloseDrainsMuxCoolCarrier(t *testing.T) {
	handler, err := NewListenerHandler(ListenerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- handler.ParseSpecialFqdn(context.Background(), server, M.Metadata{
			Source:      M.ParseSocksaddr("192.0.2.20:32000"),
			Destination: vmess.MuxDestination,
		})
	}()
	keepAlive, err := muxcool.EncodeFrame(muxcool.Frame{Status: muxcool.StatusKeepAlive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(keepAlive); err != nil {
		t.Fatal(err)
	}

	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ParseSpecialFqdn: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("mux.cool carrier was not drained")
	}
	_ = client.Close()
}
