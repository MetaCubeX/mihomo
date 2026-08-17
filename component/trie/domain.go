package trie

import (
	"errors"
	"fmt"
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

// ErrInvalidDomain means a domain pattern is invalid.
var ErrInvalidDomain = errors.New("invalid domain")

// DomainTrie contains the main logic for adding and searching nodes for domain segments.
// support wildcard domain (e.g *.google.com)
type DomainTrie[T any] struct {
	root *Node[T]
}

// ValidAndSplitDomain lower-cases and splits a domain into its dot-separated
// parts, reporting whether it is a well-formed pattern. It returns an error for
// a trailing dot ("a.com."), leading/trailing whitespace, or an empty segment,
// as well as for misplaced wildcards (see below). The error describes why the
// invalid Clash-style domain pattern was rejected.
func ValidAndSplitDomain(domain string) ([]string, error) {
	originalDomain := domain
	if domain == "" {
		return nil, invalidDomainError(originalDomain, "domain is empty")
	}

	// A trailing dot would produce an empty final segment; reject it up front.
	if domain[len(domain)-1] == '.' {
		return nil, invalidDomainError(originalDomain, "trailing dot is not allowed")
	}
	// Reject leading/trailing whitespace (a common copy-paste artifact) so it
	// isn't silently baked into a label.
	if r, _ := utf8.DecodeRuneInString(domain); unicode.IsSpace(r) {
		return nil, invalidDomainError(originalDomain, "leading whitespace is not allowed")
	}
	if r, _ := utf8.DecodeLastRuneInString(domain); unicode.IsSpace(r) {
		return nil, invalidDomainError(originalDomain, "trailing whitespace is not allowed")
	}

	domain = strings.ToLower(domain)
	parts := strings.Split(domain, domainStep)
	// A single part must be non-empty (rejects ""); for multi-part domains every
	// segment after the first must be non-empty (rejects "a..b", "a.", ".."),
	// while an empty first segment is allowed as the ".example.com" dot-wildcard.
	if len(parts) == 1 {
		if parts[0] == "" {
			return nil, invalidDomainError(originalDomain, "domain is empty")
		}
	} else {
		for i, part := range parts[1:] {
			if part == "" {
				return nil, invalidDomainError(originalDomain, fmt.Sprintf("label %d is empty", i+2))
			}
		}
	}

	// Validate wildcard placement so that DomainTrie.Search (treats a stray
	// wildcard as a literal label) and DomainSet.Has (treats the wildcard byte
	// as a wildcard) can never disagree:
	//   - complexWildcard "+" is only valid as a whole first segment of a
	//     multi-part domain, i.e. the "+.example.com" form. A bare "+", or a
	//     "+" anywhere else, is rejected.
	//   - wildcard "*" is only valid as a whole segment; a partial wildcard such
	//     as "*a" or "a*b" is rejected.
	for i, part := range parts {
		if strings.Contains(part, complexWildcard) {
			switch {
			case part != complexWildcard:
				return nil, invalidDomainError(originalDomain, fmt.Sprintf("%q wildcard must occupy the entire label %d", complexWildcard, i+1))
			case i != 0:
				return nil, invalidDomainError(originalDomain, fmt.Sprintf("%q wildcard is only allowed in the first label", complexWildcard))
			case len(parts) == 1:
				return nil, invalidDomainError(originalDomain, fmt.Sprintf("%q wildcard must be followed by another label", complexWildcard))
			}
		}
		if strings.Contains(part, wildcard) && part != wildcard {
			return nil, invalidDomainError(originalDomain, fmt.Sprintf("%q wildcard must occupy the entire label %d", wildcard, i+1))
		}
	}

	return parts, nil
}

func invalidDomainError(domain, reason string) error {
	return fmt.Errorf("%w %q: %s", ErrInvalidDomain, domain, reason)
}

// Insert adds a node to the trie.
// Support
// 1. www.example.com
// 2. *.example.com
// 3. subdomain.*.example.com
// 4. .example.com
// 5. +.example.com
func (t *DomainTrie[T]) Insert(domain string, data T) error {
	parts, err := ValidAndSplitDomain(domain)
	if err != nil {
		return err
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
	parts, err := ValidAndSplitDomain(domain)
	if err != nil || parts[0] == "" {
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
