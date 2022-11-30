package trie

import "strings"

// Node is the trie's node
type Node[T any] struct {
	children map[string]*Node[T]
	inited   bool
	data     T
}

func (n *Node[T]) getChild(s string) *Node[T] {
	if n.children == nil {
		return nil
	}
	return n.children[s]
}

func (n *Node[T]) hasChild(s string) bool {
	return n.getChild(s) != nil
}

func (n *Node[T]) addChild(s string, child *Node[T]) {
	if n.children == nil {
		n.children = map[string]*Node[T]{}
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

func (n *Node[T]) finishAdd() {
	if n.children == nil {
		return
	}
	if len(n.children) == 0 {
		n.children = nil
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
		child.finishAdd()
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
	return &Node[T]{
		children: nil,
		inited:   false,
	}
}
