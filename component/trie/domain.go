package trie

import (
	"errors"
	"github.com/Dreamacro/clash/log"
	"net"
	"strings"
)

const (
	wildcard        = "*"
	dotWildcard     = ""
	complexWildcard = "+"
	domainStep      = "."
)

// ErrInvalidDomain means insert domain is invalid
var ErrInvalidDomain = errors.New("invalid domain")

// DomainTrie contains the main logic for adding and searching nodes for domain segments.
// support wildcard domain (e.g *.google.com)
type DomainTrie struct {
	root *Node
}

func ValidAndSplitDomain(domain string) ([]string, bool) {
	if domain != "" && domain[len(domain)-1] == '.' {
		return nil, false
	}

	parts := strings.Split(domain, domainStep)
	if len(parts) == 1 {
		if parts[0] == "" {
			return nil, false
		}

		return parts, true
	}

	for _, part := range parts[1:] {
		if part == "" {
			return nil, false
		}
	}

	return parts, true
}

// Insert adds a node to the trie.
// Support
// 1. www.example.com
// 2. *.example.com
// 3. subdomain.*.example.com
// 4. .example.com
// 5. +.example.com
func (t *DomainTrie) Insert(domain string, data interface{}) error {
	parts, valid := ValidAndSplitDomain(domain)
	if !valid {
		return ErrInvalidDomain
	}

	if parts[0] == complexWildcard {
		t.insert(parts[1:], data)
		parts[0] = dotWildcard
		t.insert(parts, data)
	} else {
		t.insert(parts, data)
	}

	return nil
}

func (t *DomainTrie) insert(parts []string, data interface{}) {
	node := t.root
	// reverse storage domain part to save space
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if !node.hasChild(part) {
			node.addChild(part, newNode(nil))
		}

		node = node.getChild(part)
	}

	node.Data = data
}

// Search is the most important part of the Trie.
// Priority as:
// 1. static part
// 2. wildcard domain
// 2. dot wildcard domain
func (t *DomainTrie) Search(domain string) *Node {
	parts, valid := ValidAndSplitDomain(domain)
	if !valid || parts[0] == "" {
		return nil
	}

	n := t.search(t.root, parts)

	if n == nil || n.Data == nil {
		return nil
	}

	return n
}

func (t *DomainTrie) search(node *Node, parts []string) *Node {
	if len(parts) == 0 {
		return node
	}

	if c := node.getChild(parts[len(parts)-1]); c != nil {
		if n := t.search(c, parts[:len(parts)-1]); n != nil {
			return n
		}
	}

	if c := node.getChild(wildcard); c != nil {
		if n := t.search(c, parts[:len(parts)-1]); n != nil {
			return n
		}
	}

	return node.getChild(dotWildcard)
}

// New returns a new, empty Trie.
func New() *DomainTrie {
	return &DomainTrie{root: newNode(nil)}
}

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
	ip, isIpv4 := checkAndConverterIp(ip)
	if ip == nil {
		return false
	}

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
	return trie.IsContain(net.ParseIP(ipString))
}

func ipCidrToSubIpCidr(ipNet *net.IPNet) ([]net.IP, int, bool, error) {
	maskSize, _ := ipNet.Mask.Size()
	var (
		ipList      []net.IP
		newMaskSize int
		isIpv4      bool
		err         error
	)

	ip, isIpv4 := checkAndConverterIp(ipNet.IP)
	ipList, newMaskSize, err = subIpCidr(ip, maskSize, isIpv4)

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
	for i := 0; i < subIpCidrNum; i++ {
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

// return net.IP To4 or To16 and is ipv4
func checkAndConverterIp(ip net.IP) (net.IP, bool) {
	ipResult := ip.To4()
	if ipResult == nil {
		ipResult = ip.To16()
		if ipResult == nil {
			return nil, false
		}

		return ipResult, false
	}

	return ipResult, true
}

var (
	ErrorOverMaxValue = errors.New("the value don't over max value")
)

type IpCidrNode struct {
	Mark     bool
	child    map[uint32]*IpCidrNode
	maxValue uint32
}

func NewIpCidrNode(mark bool, maxValue uint32) *IpCidrNode {
	ipCidrNode := &IpCidrNode{
		Mark:     mark,
		child:    map[uint32]*IpCidrNode{},
		maxValue: maxValue,
	}

	return ipCidrNode
}

func (n *IpCidrNode) addChild(value uint32) error {
	if value > n.maxValue {
		return ErrorOverMaxValue
	}

	n.child[value] = NewIpCidrNode(false, n.maxValue)
	return nil
}

func (n *IpCidrNode) hasChild(value uint32) bool {
	return n.getChild(value) != nil
}

func (n *IpCidrNode) getChild(value uint32) *IpCidrNode {
	if value <= n.maxValue {
		return n.child[value]
	}

	return nil
}
