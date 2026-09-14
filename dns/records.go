package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

func newRecordsClient(addr string) recordsClient {
	return recordsClient{
		rcode: D.RcodeSuccess,
		addr:  "records://" + addr,
	}
}

type recordsClient struct {
	rcode int
	addr  string
}

var _ dnsClient = (*recordsClient)(nil)

func (r recordsClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	m.Response = true
	m.Rcode = r.rcode

	// split ip
	ips := strings.Split(r.addr[len("records://"):]+",", ",")
	ip4 := ips[0]
	ip6 := ips[1]

	var q *D.Question
	if len(m.Question) > 0 {
		q = &m.Question[0]
	} else {
		return nil, fmt.Errorf("[DNS] ns-policy records resolve failed: no Question")
	}

	// queryType A/AAAA return ip4/6 records
	if q.Qtype == D.TypeA {
		rr := &D.A{
			Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip4),
		}
		m.Answer = append(m.Answer, rr)
	}

	if q.Qtype == D.TypeAAAA {
		rr := &D.AAAA{
			Hdr:  D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 60},
			AAAA: net.ParseIP(ip6),
		}
		m.Answer = append(m.Answer, rr)
	}

	log.Debugln("[DNS] ns-policy %s --> %s from %s", msgToDomain(m), msgToLogString(m), r.Address())

	return m, nil
}

func (r recordsClient) Address() string {
	return r.addr
}

func (r recordsClient) ResetConnection() {}
