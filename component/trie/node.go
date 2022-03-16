package trie

// Node is the trie's node
type Node struct {
	children map[string]*Node
	Data     any
}

func (n *Node) getChild(s string) *Node {
	return n.children[s]
}

func (n *Node) hasChild(s string) bool {
	return n.getChild(s) != nil
}

func (n *Node) addChild(s string, child *Node) {
	n.children[s] = child
}

func newNode(data any) *Node {
	return &Node{
		Data:     data,
		children: map[string]*Node{},
	}
}
