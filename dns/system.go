package dns

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	D "github.com/miekg/dns"
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
