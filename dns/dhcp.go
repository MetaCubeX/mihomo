package dns

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"github.com/Dreamacro/clash/component/dhcp"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/component/resolver"

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

	ifaceAddr *net.IPNet
	done      chan struct{}
	clients   []dnsClient
	err       error
}

func (d *dhcpClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()

	return d.ExchangeContext(ctx, m)
}

func (d *dhcpClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	clients, err := d.resolve(ctx)
	if err != nil {
		return nil, err
	}

	return batchExchange(ctx, clients, m)
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

	addr, err := ifaceObj.PickIPv4Addr(nil)
	if err != nil {
		return false, err
	}

	if time.Now().Before(d.dnsInvalidate) && d.ifaceAddr.IP.Equal(addr.IP) && bytes.Equal(d.ifaceAddr.Mask, addr.Mask) {
		return false, nil
	}

	d.dnsInvalidate = time.Now().Add(DHCPTTL)
	d.ifaceAddr = addr

	return d.done == nil, nil
}

func newDHCPClient(ifaceName string) *dhcpClient {
	return &dhcpClient{ifaceName: ifaceName}
}
