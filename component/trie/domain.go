package trie

import (
	"errors"
	"strings"
)

const (
	wildcard        = "*"
	dotWildcard     = ""
	complexWildcard = "+"
	domainStep      = "."
)

var (
	// ErrInvalidDomain means insert domain is invalid
	ErrInvalidDomain = errors.New("invalid domain")
)

// DomainTrie contains the main logic for adding and searching nodes for domain segments.
// support wildcard domain (e.g *.google.com)
type DomainTrie struct {
	root *Node
}

func validAndSplitDomain(domain string) ([]string, bool) {
	if domain != "" && domain[len(domain)-1] == '.' {
		return nil, false
	}

	parts := strings.Split(domain, domainStep)
	if len(parts) == 1 {
		return nil, false
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
	parts, valid := validAndSplitDomain(domain)
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
	parts, valid := validAndSplitDomain(domain)
	if !valid || parts[0] == "" {
		return nil
	}

	n := t.root
	var dotWildcardNode *Node
	var wildcardNode *Node
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		if node := n.getChild(dotWildcard); node != nil {
			dotWildcardNode = node
		}

		child := n.getChild(part)
		if child == nil && wildcardNode != nil {
			child = wildcardNode.getChild(part)
		}
		wildcardNode = n.getChild(wildcard)

		n = child
		if n == nil {
			n = wildcardNode
			wildcardNode = nil
		}

		if n == nil {
			break
		}
	}

	if n == nil {
		if dotWildcardNode != nil {
			return dotWildcardNode
		}
		return nil
	}

	if n.Data == nil {
		return nil
	}

	return n
}

// New returns a new, empty Trie.
func New() *DomainTrie {
	return &DomainTrie{root: newNode(nil)}
}
