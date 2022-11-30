package trie

import "strings"

// Node is the trie's node
type Node[T any] struct {
	childNode *Node[T] // optimize for only one child
	childStr  string
	children  map[string]*Node[T]
	inited    bool
	data      T
}

func (n *Node[T]) getChild(s string) *Node[T] {
	if n.children == nil {
		if n.childNode != nil && n.childStr == s {
			return n.childNode
		}
		return nil
	}
	return n.children[s]
}

func (n *Node[T]) hasChild(s string) bool {
	return n.getChild(s) != nil
}

func (n *Node[T]) addChild(s string, child *Node[T]) {
	if n.children == nil {
		if n.childNode == nil {
			n.childStr = s
			n.childNode = child
			return
		}
		n.children = map[string]*Node[T]{}
		if n.childNode != nil {
			n.children[n.childStr] = n.childNode
		}
		n.childStr = ""
		n.childNode = nil
	}

	n.children[s] = child
}

func (n *Node[T]) getOrNewChild(s string) *Node[T] {
	node := n.getChild(s)
	if node == nil {
		node = newNode[T]()
		n.addChild(s, node)
	}
	return node
}

func (n *Node[T]) optimize() {
	if len(n.childStr) > 0 {
		n.childStr = strings.Clone(n.childStr)
	}
	if n.childNode != nil {
		n.childNode.optimize()
	}
	if n.children == nil {
		return
	}
	switch len(n.children) {
	case 0:
		n.children = nil
		return
	case 1:
		for key := range n.children {
			n.childStr = key
			n.childNode = n.children[key]
		}
		n.children = nil
		n.optimize()
		return
	}
	children := make(map[string]*Node[T], len(n.children)) // avoid map reallocate memory
	for key := range n.children {
		child := n.children[key]
		if child == nil {
			continue
		}
		switch key { // try to save string's memory
		case wildcard:
			key = wildcard
		case dotWildcard:
			key = dotWildcard
		default:
			key = strings.Clone(key)
		}
		children[key] = child
		child.optimize()
	}
	n.children = children
}

func (n *Node[T]) isEmpty() bool {
	if n == nil || n.inited == false {
		return true
	}
	return false
}

func (n *Node[T]) setData(data T) {
	n.data = data
	n.inited = true
}

func (n *Node[T]) Data() T {
	return n.data
}

func newNode[T any]() *Node[T] {
	return &Node[T]{}
}
