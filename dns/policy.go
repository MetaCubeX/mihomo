package dns

type Policy struct {
	data []dnsClient
}

func (p *Policy) GetData() []dnsClient {
	return p.data
}

func (p *Policy) Compare(p2 *Policy) int {
	if p2 == nil {
		return 1
	}
	l1 := len(p.data)
	l2 := len(p2.data)
	if l1 == l2 {
		return 0
	}
	if l1 > l2 {
		return 1
	}
	return -1
}

func NewPolicy(data []dnsClient) *Policy {
	return &Policy{
		data: data,
	}
}
