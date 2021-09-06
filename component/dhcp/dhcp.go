package dhcp

import (
	"context"
	"errors"
	"math/rand"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

var (
	ErrNotResponding = errors.New("DHCP not responding")
	ErrNotFound      = errors.New("DNS option not found")
)

func ResolveDNSFromDHCP(context context.Context, ifaceName string) ([]net.IP, error) {
	conn, err := ListenDHCPClient(context, ifaceName)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result := make(chan []net.IP, 1)

	discovery, err := dhcpv4.NewDiscovery(randomHardware(), dhcpv4.WithBroadcast(true), dhcpv4.WithRequestedOptions(dhcpv4.OptionDomainNameServer))
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

func receiveOffer(conn net.PacketConn, id dhcpv4.TransactionID, result chan<- []net.IP) {
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
		if len(dns) == 0 {
			return
		}

		result <- dns

		return
	}
}

func randomHardware() net.HardwareAddr {
	addr := make(net.HardwareAddr, 6)

	addr[0] = 0xff

	for i := 1; i < len(addr); i++ {
		addr[i] = byte(rand.Intn(254) + 1)
	}

	return addr
}
