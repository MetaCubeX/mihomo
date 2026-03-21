package trie

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
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
type DomainTrie[T any] struct {
	root *Node[T]
}

func ValidAndSplitDomain(domain string) ([]string, bool) {
	if domain != "" && domain[len(domain)-1] == '.' {
		return nil, false
	}
	if domain != "" {
		if r, _ := utf8.DecodeRuneInString(domain); unicode.IsSpace(r) {
			return nil, false
		}
		if r, _ := utf8.DecodeLastRuneInString(domain); unicode.IsSpace(r) {
			return nil, false
		}
	}
	domain = strings.ToLower(domain)
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
func (t *DomainTrie[T]) Insert(domain string, data T) error {
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

func (t *DomainTrie[T]) insert(parts []string, data T) {
	node := t.root
	// reverse storage domain part to save space
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		node = node.getOrNewChild(part)
	}

	node.setData(data)
}

// Search is the most important part of the Trie.
// Priority as:
// 1. static part
// 2. wildcard domain
// 2. dot wildcard domain
func (t *DomainTrie[T]) Search(domain string) *Node[T] {
	parts, valid := ValidAndSplitDomain(domain)
	if !valid || parts[0] == "" {
		return nil
	}

	n := t.search(t.root, parts)

	if n.isEmpty() {
		return nil
	}

	return n
}

func (t *DomainTrie[T]) search(node *Node[T], parts []string) *Node[T] {
	if len(parts) == 0 {
		return node
	}

	if c := node.getChild(parts[len(parts)-1]); c != nil {
		if n := t.search(c, parts[:len(parts)-1]); !n.isEmpty() {
			return n
		}
	}

	if c := node.getChild(wildcard); c != nil {
		if n := t.search(c, parts[:len(parts)-1]); !n.isEmpty() {
			return n
		}
	}

	return node.getChild(dotWildcard)
}

func (t *DomainTrie[T]) Optimize() {
	t.root.optimize()
}

func (t *DomainTrie[T]) Foreach(fn func(domain string, data T) bool) {
	for key, data := range t.root.getChildren() {
		recursion([]string{key}, data, fn)
		if !data.isEmpty() {
			if !fn(joinDomain([]string{key}), data.data) {
				return
			}
		}
	}
}

func (t *DomainTrie[T]) IsEmpty() bool {
	if t == nil || t.root == nil {
		return true
	}
	return len(t.root.getChildren()) == 0
}

func recursion[T any](items []string, node *Node[T], fn func(domain string, data T) bool) bool {
	for key, data := range node.getChildren() {
		newItems := append([]string{key}, items...)
		if !data.isEmpty() {
			domain := joinDomain(newItems)
			if domain[0] == domainStepByte {
				domain = complexWildcard + domain
			}
			if !fn(domain, data.Data()) {
				return false
			}
		}
		if !recursion(newItems, data, fn) {
			return false
		}
	}
	return true
}

func joinDomain(items []string) string {
	return strings.Join(items, domainStep)
}

// New returns a new, empty Trie.
func New[T any]() *DomainTrie[T] {
	return &DomainTrie[T]{root: newNode[T]()}
}
