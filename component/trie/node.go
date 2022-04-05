package trie

// Node is the trie's node
type Node[T comparable] struct {
	children map[string]*Node[T]
	Data     T
}

func (n *Node[T]) getChild(s string) *Node[T] {
	return n.children[s]
}

func (n *Node[T]) hasChild(s string) bool {
	return n.getChild(s) != nil
}

func (n *Node[T]) addChild(s string, child *Node[T]) {
	n.children[s] = child
}

func newNode[T comparable](data T) *Node[T] {
	return &Node[T]{
		Data:     data,
		children: map[string]*Node[T]{},
	}
}

func getZero[T comparable]() T {
	var result T
	return result
}
