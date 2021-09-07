package dhcp

import (
	"context"
	"net"
	"runtime"

	"github.com/Dreamacro/clash/component/dialer"
)

func ListenDHCPClient(ctx context.Context, ifaceName string) (net.PacketConn, error) {
	listenAddr := "0.0.0.0:68"
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		listenAddr = "255.255.255.255:68"
	}

	return dialer.ListenPacket(ctx, "udp4", listenAddr, dialer.WithInterface(ifaceName), dialer.WithAddrReuse(true))
}
