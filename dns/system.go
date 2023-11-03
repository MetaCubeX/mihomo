package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

const (
	SystemDnsFlushTime   = 5 * time.Minute
	SystemDnsDeleteTimes = 12 // 12*5 = 60min
)

type systemDnsClient struct {
	disableTimes uint32
	dnsClient
}

type systemClient struct {
	mu         sync.Mutex
	dnsClients map[string]*systemDnsClient
	lastFlush  time.Time
}

func (c *systemClient) getDnsClients() ([]dnsClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	if time.Since(c.lastFlush) > SystemDnsFlushTime {
		var nameservers []string
		if nameservers, err = dnsReadConfig(); err == nil {
			log.Debugln("[DNS] system dns update to %s", nameservers)
			for _, addr := range nameservers {
				if _, ok := c.dnsClients[addr]; !ok {
					clients := transform(
						[]NameServer{{
							Addr: net.JoinHostPort(addr, "53"),
							Net:  "udp",
						}},
						nil,
					)
					if len(clients) > 0 {
						c.dnsClients[addr] = &systemDnsClient{
							disableTimes: 0,
							dnsClient:    clients[0],
						}
					}
				}
			}
			available := 0
			for nameserver, sdc := range c.dnsClients {
				if slices.Contains(nameservers, nameserver) {
					sdc.disableTimes = 0 // enable
					available++
				} else {
					if sdc.disableTimes > SystemDnsDeleteTimes {
						delete(c.dnsClients, nameserver) // drop too old dnsClient
					} else {
						sdc.disableTimes++
					}
				}
			}
			if available > 0 {
				c.lastFlush = time.Now()
			}
		}
	}
	dnsClients := make([]dnsClient, 0, len(c.dnsClients))
	for _, sdc := range c.dnsClients {
		if sdc.disableTimes == 0 {
			dnsClients = append(dnsClients, sdc.dnsClient)
		}
	}
	if len(dnsClients) > 0 {
		return dnsClients, nil
	}
	return nil, err
}

func (c *systemClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	dnsClients, err := c.getDnsClients()
	if err != nil {
		return
	}
	msg, _, err = batchExchange(ctx, dnsClients, m)
	return
}

// Address implements dnsClient
func (c *systemClient) Address() string {
	dnsClients, _ := c.getDnsClients()
	addrs := make([]string, 0, len(dnsClients))
	for _, c := range dnsClients {
		addrs = append(addrs, c.Address())
	}
	return fmt.Sprintf("system(%s)", strings.Join(addrs, ","))
}

var _ dnsClient = (*systemClient)(nil)

func newSystemClient() *systemClient {
	return &systemClient{
		dnsClients: map[string]*systemDnsClient{},
	}
}
