package dns

import (
	"net"
	"testing"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestExchangeContextTypeA(t *testing.T) {
	// new recordsClient
	ip4 := "127.0.0.1"
	recordsCli := newRecordsClient(ip4 + ",2001:0db8:85a3:0000:0000:8a2e:0370:7334")

	// new D.Msg
	question := D.Question{
		Name:   "android-gateway.com.cn",
		Qtype:  D.TypeA,
		Qclass: D.ClassANY,
	}

	msg := &D.Msg{
		Question: []D.Question{question},
	}

	// test get answer [A]
	replyMsg, _ := recordsCli.ExchangeContext(nil, msg)

	a, ok := replyMsg.Answer[0].(*D.A)

	assert.Equal(t, true, ok)
	assert.Equal(t, ip4, a.A.String())
	assert.Implements(t, (*D.RR)(nil), replyMsg.Answer[0])
}

func TestExchangeContextTypeAAAA(t *testing.T) {
	// new recordsClient
	ip6 := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	recordsCli := newRecordsClient("127.0.0.1," + ip6)

	// new D.Msg
	question := D.Question{
		Name:   "android-gateway.com.cn",
		Qtype:  D.TypeAAAA,
		Qclass: D.ClassANY,
	}

	msg := &D.Msg{
		Question: []D.Question{question},
	}

	// test get answer [AAAA]
	replyMsg, _ := recordsCli.ExchangeContext(nil, msg)

	reply, ok := replyMsg.Answer[0].(*D.AAAA)

	assert.Equal(t, true, ok)
	assert.Equal(t, net.ParseIP(ip6).String(), reply.AAAA.String())
	assert.Implements(t, (*D.RR)(nil), replyMsg.Answer[0])
}
