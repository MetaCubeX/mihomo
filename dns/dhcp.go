package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dhcp"
	"github.com/metacubex/mihomo/component/iface"
	D "github.com/miekg/dns"
)

const (
	IfaceTTL    = time.Second * 20
	DHCPTTL     = time.Hour
	DHCPTimeout = time.Minute
)

type dhcpClient struct {
	ifaceName string

	lock            sync.Mutex
	ifaceInvalidate time.Time
	dnsInvalidate   time.Time

	ifaceAddr netip.Prefix
	done      chan struct{}
	clients   []dnsClient
	err       error
}

var _ dnsClient = (*dhcpClient)(nil)

// Address implements dnsClient
func (d *dhcpClient) Address() string {
	addrs := make([]string, 0)
	for _, c := range d.clients {
		addrs = append(addrs, c.Address())
	}
	return strings.Join(addrs, ",")
}

func (d *dhcpClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	clients, err := d.resolve(ctx)
	if err != nil {
		return nil, err
	}

	msg, _, err = batchExchange(ctx, clients, m)
	return
}

func (d *dhcpClient) ResetConnection() {
	for _, client := range d.clients {
		client.ResetConnection()
	}
}

func (d *dhcpClient) resolve(ctx context.Context) ([]dnsClient, error) {
	d.lock.Lock()

	invalidated, err := d.invalidate()
	if err != nil {
		d.err = err
	} else if invalidated {
		done := make(chan struct{})

		d.done = done

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), DHCPTimeout)
			defer cancel()

			var res []dnsClient
			dns, err := dhcp.ResolveDNSFromDHCP(ctx, d.ifaceName)
			// dns never empty if err is nil
			if err == nil {
				nameserver := make([]NameServer, 0, len(dns))
				for _, item := range dns {
					nameserver = append(nameserver, NameServer{
						Addr:      net.JoinHostPort(item.String(), "53"),
						Interface: d.ifaceName,
					})
				}

				res = transform(nameserver, nil)
			}

			d.lock.Lock()
			defer d.lock.Unlock()

			close(done)

			d.done = nil
			d.clients = res
			d.err = err
		}()
	}

	d.lock.Unlock()

	for {
		d.lock.Lock()

		res, err, done := d.clients, d.err, d.done

		d.lock.Unlock()

		// initializing
		if res == nil && err == nil {
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// dirty return
		return res, err
	}
}

func (d *dhcpClient) invalidate() (bool, error) {
	if time.Now().Before(d.ifaceInvalidate) {
		return false, nil
	}

	d.ifaceInvalidate = time.Now().Add(IfaceTTL)

	ifaceObj, err := iface.ResolveInterface(d.ifaceName)
	if err != nil {
		return false, err
	}

	addr, err := ifaceObj.PickIPv4Addr(netip.Addr{})
	if err != nil {
		return false, err
	}

	if time.Now().Before(d.dnsInvalidate) && d.ifaceAddr == addr {
		return false, nil
	}

	d.dnsInvalidate = time.Now().Add(DHCPTTL)
	d.ifaceAddr = addr

	return d.done == nil, nil
}

func newDHCPClient(ifaceName string) *dhcpClient {
	return &dhcpClient{ifaceName: ifaceName}
}
