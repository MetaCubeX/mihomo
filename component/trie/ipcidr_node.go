package trie

import "errors"

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
