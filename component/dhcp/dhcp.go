package dhcp

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/nnip"
	"github.com/metacubex/mihomo/component/iface"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

var (
	ErrNotResponding = errors.New("DHCP not responding")
	ErrNotFound      = errors.New("DNS option not found")
)

func ResolveDNSFromDHCP(context context.Context, ifaceName string) ([]netip.Addr, error) {
	conn, err := ListenDHCPClient(context, ifaceName)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	result := make(chan []netip.Addr, 1)

	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return nil, err
	}

	discovery, err := dhcpv4.NewDiscovery(ifaceObj.HardwareAddr, dhcpv4.WithBroadcast(true), dhcpv4.WithRequestedOptions(dhcpv4.OptionDomainNameServer))
	if err != nil {
		return nil, err
	}

	go receiveOffer(conn, discovery.TransactionID, result)

	_, err = conn.WriteTo(discovery.ToBytes(), &net.UDPAddr{IP: net.IPv4bcast, Port: 67})
	if err != nil {
		return nil, err
	}

	select {
	case r, ok := <-result:
		if !ok {
			return nil, ErrNotFound
		}
		return r, nil
	case <-context.Done():
		return nil, ErrNotResponding
	}
}

func receiveOffer(conn net.PacketConn, id dhcpv4.TransactionID, result chan<- []netip.Addr) {
	defer close(result)

	buf := make([]byte, dhcpv4.MaxMessageSize)

	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		pkt, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue
		}

		if pkt.MessageType() != dhcpv4.MessageTypeOffer {
			continue
		}

		if pkt.TransactionID != id {
			continue
		}

		dns := pkt.DNS()
		l := len(dns)
		if l == 0 {
			return
		}

		dnsAddr := make([]netip.Addr, l)
		for i := 0; i < l; i++ {
			dnsAddr[i] = nnip.IpToAddr(dns[i])
		}

		result <- dnsAddr

		return
	}
}
