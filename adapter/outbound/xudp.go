package outbound

import (
	"errors"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
)

// xudpDestination keeps a known domain, or a real IP when the packet has no domain.
// A fake-ip is not used as the remote destination.
func xudpDestination(metadata *C.Metadata) (M.Socksaddr, error) {
	if metadata.Host != "" {
		return M.Socksaddr{
			Fqdn: metadata.Host,
			Port: metadata.DstPort,
		}, nil
	}
	if metadata.DstIP.IsValid() && !resolver.IsFakeIP(metadata.DstIP) {
		return M.SocksaddrFrom(metadata.DstIP, metadata.DstPort), nil
	}
	return M.Socksaddr{}, errors.New("invalid udp destination")
}
