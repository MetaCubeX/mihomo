package dns

import (
	"context"
	"fmt"

	D "github.com/miekg/dns"
)

func newRCodeClient(addr string) rcodeClient {
	var rcode int
	switch addr {
	case "success":
		rcode = D.RcodeSuccess
	case "format_error":
		rcode = D.RcodeFormatError
	case "server_failure":
		rcode = D.RcodeServerFailure
	case "name_error":
		rcode = D.RcodeNameError
	case "not_implemented":
		rcode = D.RcodeNotImplemented
	case "refused":
		rcode = D.RcodeRefused
	default:
		panic(fmt.Errorf("unsupported RCode type: %s", addr))
	}

	return rcodeClient{
		rcode: rcode,
		addr:  "rcode://" + addr,
	}
}

type rcodeClient struct {
	rcode int
	addr  string
}

var _ dnsClient = rcodeClient{}

func (r rcodeClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	m.Response = true
	m.Rcode = r.rcode
	return m, nil
}

func (r rcodeClient) Address() string {
	return r.addr
}

func (r rcodeClient) ResetConnection() {}
