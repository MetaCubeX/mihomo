package trie

import (
	"net"

	"github.com/metacubex/mihomo/log"
)

type IPV6 bool

const (
	ipv4GroupMaxValue = 0xFF
	ipv6GroupMaxValue = 0xFFFF
)

type IpCidrTrie struct {
	ipv4Trie *IpCidrNode
	ipv6Trie *IpCidrNode
}

func NewIpCidrTrie() *IpCidrTrie {
	return &IpCidrTrie{
		ipv4Trie: NewIpCidrNode(false, ipv4GroupMaxValue),
		ipv6Trie: NewIpCidrNode(false, ipv6GroupMaxValue),
	}
}

func (trie *IpCidrTrie) AddIpCidr(ipCidr *net.IPNet) error {
	subIpCidr, subCidr, isIpv4, err := ipCidrToSubIpCidr(ipCidr)
	if err != nil {
		return err
	}

	for _, sub := range subIpCidr {
		addIpCidr(trie, isIpv4, sub, subCidr/8)
	}

	return nil
}

func (trie *IpCidrTrie) AddIpCidrForString(ipCidr string) error {
	_, ipNet, err := net.ParseCIDR(ipCidr)
	if err != nil {
		return err
	}

	return trie.AddIpCidr(ipNet)
}

func (trie *IpCidrTrie) IsContain(ip net.IP) bool {
	if ip == nil {
		return false
	}
	isIpv4 := len(ip) == net.IPv4len
	var groupValues []uint32
	var ipCidrNode *IpCidrNode

	if isIpv4 {
		ipCidrNode = trie.ipv4Trie
		for _, group := range ip {
			groupValues = append(groupValues, uint32(group))
		}
	} else {
		ipCidrNode = trie.ipv6Trie
		for i := 0; i < len(ip); i += 2 {
			groupValues = append(groupValues, getIpv6GroupValue(ip[i], ip[i+1]))
		}
	}

	return search(ipCidrNode, groupValues) != nil
}

func (trie *IpCidrTrie) IsContainForString(ipString string) bool {
	ip := net.ParseIP(ipString)
	// deal with 4in6
	actualIp := ip.To4()
	if actualIp == nil {
		actualIp = ip
	}
	return trie.IsContain(actualIp)
}

func ipCidrToSubIpCidr(ipNet *net.IPNet) ([]net.IP, int, bool, error) {
	maskSize, _ := ipNet.Mask.Size()
	var (
		ipList      []net.IP
		newMaskSize int
		isIpv4      bool
		err         error
	)
	isIpv4 = len(ipNet.IP) == net.IPv4len
	ipList, newMaskSize, err = subIpCidr(ipNet.IP, maskSize, isIpv4)

	return ipList, newMaskSize, isIpv4, err
}

func subIpCidr(ip net.IP, maskSize int, isIpv4 bool) ([]net.IP, int, error) {
	var subIpCidrList []net.IP
	groupSize := 8
	if !isIpv4 {
		groupSize = 16
	}

	if maskSize%groupSize == 0 {
		return append(subIpCidrList, ip), maskSize, nil
	}

	lastByteMaskSize := maskSize % 8
	lastByteMaskIndex := maskSize / 8
	subIpCidrNum := 0xFF >> lastByteMaskSize
	for i := 0; i <= subIpCidrNum; i++ {
		subIpCidr := make([]byte, len(ip))
		copy(subIpCidr, ip)
		subIpCidr[lastByteMaskIndex] += byte(i)
		subIpCidrList = append(subIpCidrList, subIpCidr)
	}

	newMaskSize := (lastByteMaskIndex + 1) * 8
	if !isIpv4 {
		newMaskSize = (lastByteMaskIndex/2 + 1) * 16
	}

	return subIpCidrList, newMaskSize, nil
}

func addIpCidr(trie *IpCidrTrie, isIpv4 bool, ip net.IP, groupSize int) {
	if isIpv4 {
		addIpv4Cidr(trie, ip, groupSize)
	} else {
		addIpv6Cidr(trie, ip, groupSize)
	}
}

func addIpv4Cidr(trie *IpCidrTrie, ip net.IP, groupSize int) {
	preNode := trie.ipv4Trie
	node := preNode.getChild(uint32(ip[0]))
	if node == nil {
		err := preNode.addChild(uint32(ip[0]))
		if err != nil {
			return
		}

		node = preNode.getChild(uint32(ip[0]))
	}

	for i := 1; i < groupSize; i++ {
		if node.Mark {
			return
		}

		groupValue := uint32(ip[i])
		if !node.hasChild(groupValue) {
			err := node.addChild(groupValue)
			if err != nil {
				log.Errorln(err.Error())
			}
		}

		preNode = node
		node = node.getChild(groupValue)
		if node == nil {
			err := preNode.addChild(uint32(ip[i-1]))
			if err != nil {
				return
			}

			node = preNode.getChild(uint32(ip[i-1]))
		}
	}

	node.Mark = true
	cleanChild(node)
}

func addIpv6Cidr(trie *IpCidrTrie, ip net.IP, groupSize int) {
	preNode := trie.ipv6Trie
	node := preNode.getChild(getIpv6GroupValue(ip[0], ip[1]))
	if node == nil {
		err := preNode.addChild(getIpv6GroupValue(ip[0], ip[1]))
		if err != nil {
			return
		}

		node = preNode.getChild(getIpv6GroupValue(ip[0], ip[1]))
	}

	for i := 2; i < groupSize; i += 2 {
		if ip[i] == 0 && ip[i+1] == 0 {
			node.Mark = true
		}

		if node.Mark {
			return
		}

		groupValue := getIpv6GroupValue(ip[i], ip[i+1])
		if !node.hasChild(groupValue) {
			err := node.addChild(groupValue)
			if err != nil {
				log.Errorln(err.Error())
			}
		}

		preNode = node
		node = node.getChild(groupValue)
		if node == nil {
			err := preNode.addChild(getIpv6GroupValue(ip[i-2], ip[i-1]))
			if err != nil {
				return
			}

			node = preNode.getChild(getIpv6GroupValue(ip[i-2], ip[i-1]))
		}
	}

	node.Mark = true
	cleanChild(node)
}

func getIpv6GroupValue(high, low byte) uint32 {
	return (uint32(high) << 8) | uint32(low)
}

func cleanChild(node *IpCidrNode) {
	for i := uint32(0); i < uint32(len(node.child)); i++ {
		delete(node.child, i)
	}
}

func search(root *IpCidrNode, groupValues []uint32) *IpCidrNode {
	node := root.getChild(groupValues[0])
	if node == nil || node.Mark {
		return node
	}

	for _, value := range groupValues[1:] {
		if !node.hasChild(value) {
			return nil
		}

		node = node.getChild(value)

		if node == nil || node.Mark {
			return node
		}
	}

	return nil
}
