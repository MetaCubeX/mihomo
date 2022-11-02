package trie

// Node is the trie's node
type Node[T any] struct {
	children map[string]*Node[T]
	inited   bool
	data     T
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
		children: map[string]*Node[T]{},
		inited:   false,
		data:     getZero[T](),
	}
}

func getZero[T any]() T {
	var result T
	return result
}
