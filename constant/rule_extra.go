package constant

import "net"

type RuleExtra struct {
	Network   NetWork
	SourceIPs []*net.IPNet
}

func (re *RuleExtra) NotMatchNetwork(network NetWork) bool {
	return re.Network != ALLNet && re.Network != network
}

func (re *RuleExtra) NotMatchSourceIP(srcIP net.IP) bool {
	if re.SourceIPs == nil {
		return false
	}

	for _, ips := range re.SourceIPs {
		if ips.Contains(srcIP) {
			return false
		}
	}
	return true
}
