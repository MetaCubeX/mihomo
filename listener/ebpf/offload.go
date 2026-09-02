package ebpf

import (
	"container/heap"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// RoutingAction is the final routing result observed by Mihomo. The
// offloader deliberately has no UNKNOWN state: callers must only report a
// completed rule decision.
type RoutingAction uint8

const (
	Direct RoutingAction = iota + 1
	Proxy
)

// DestinationSets is the complete dynamic policy delta. Proxy is a veto: an
// address must never be present in both desired sets after a successful call.
// A destination change is only used by the BPF program while creating a new
// flow; it is never a request to alter FLOW_OWNER.
type DestinationSets struct {
	DirectAdd    []netip.Addr
	DirectRemove []netip.Addr
	ProxyAdd     []netip.Addr
	ProxyRemove  []netip.Addr
}

// DestinationMap applies a coherent dynamic policy update. Implementations
// must return an error without claiming it is fully applied; the Offloader
// retains the complete diff and retries it.
type DestinationMap interface {
	Apply(DestinationSets) error
}

type observedDomain struct {
	ips       map[netip.Addr]struct{}
	action    RoutingAction
	expiresAt time.Time
	sequence  uint64
}

type expiry struct {
	domain   string
	deadline time.Time
	sequence uint64
}

type expiryHeap []expiry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].deadline.Before(h[j].deadline) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(value any)    { *h = append(*h, value.(expiry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

// Offloader resolves DNS observations by ownership, rather than treating an
// IP as a property of a single domain. This makes shared CDN addresses safe:
// any live PROXY owner wins over every DIRECT owner.
type Offloader struct {
	mu            sync.Mutex
	now           func() time.Time
	writer        DestinationMap
	domains       map[string]observedDomain
	owners        map[netip.Addr]map[string]RoutingAction
	desiredDirect map[netip.Addr]struct{}
	desiredProxy  map[netip.Addr]struct{}
	appliedDirect map[netip.Addr]struct{}
	appliedProxy  map[netip.Addr]struct{}
	dirty         bool
	sequence      uint64
	expires       expiryHeap
}

func NewOffloader(writer DestinationMap) *Offloader {
	return &Offloader{
		now:           time.Now,
		writer:        writer,
		domains:       make(map[string]observedDomain),
		owners:        make(map[netip.Addr]map[string]RoutingAction),
		desiredDirect: make(map[netip.Addr]struct{}),
		desiredProxy:  make(map[netip.Addr]struct{}),
		appliedDirect: make(map[netip.Addr]struct{}),
		appliedProxy:  make(map[netip.Addr]struct{}),
	}
}

// Observe records a final routing decision using its DNS TTL. A zero or
// negative TTL expires immediately; it is never silently extended.
func (o *Offloader) Observe(domain string, ips []netip.Addr, ttl time.Duration, action RoutingAction) error {
	if o == nil {
		return errors.New("eBPF direct offloader is nil")
	}
	if domain = strings.ToLower(strings.TrimSpace(domain)); domain == "" {
		return errors.New("eBPF direct offloader requires a domain")
	}
	if action != Direct && action != Proxy {
		return errors.New("eBPF direct offloader requires DIRECT or PROXY")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.expireLocked(o.now())
	o.removeDomainLocked(domain)
	o.sequence++
	observation := observedDomain{ips: make(map[netip.Addr]struct{}), action: action, expiresAt: o.now().Add(ttl), sequence: o.sequence}
	for _, ip := range ips {
		ip = ip.Unmap()
		if !offloadableAddress(ip) {
			continue
		}
		observation.ips[ip] = struct{}{}
		owners := o.owners[ip]
		if owners == nil {
			owners = make(map[string]RoutingAction)
			o.owners[ip] = owners
		}
		owners[domain] = action
	}
	o.domains[domain] = observation
	heap.Push(&o.expires, expiry{domain: domain, deadline: observation.expiresAt, sequence: observation.sequence})
	o.reconcileLocked()
	return o.flushLocked()
}

// Expire removes all observations whose real TTL elapsed and retries an
// earlier failed map update even if nothing expires in this call.
func (o *Offloader) Expire() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.expireLocked(o.now())
	o.reconcileLocked()
	return o.flushLocked()
}

func (o *Offloader) expireLocked(now time.Time) {
	for o.expires.Len() != 0 && !o.expires[0].deadline.After(now) {
		next := heap.Pop(&o.expires).(expiry)
		current, ok := o.domains[next.domain]
		if !ok || current.sequence != next.sequence {
			continue // stale heap deadline after a newer DNS response
		}
		o.removeDomainLocked(next.domain)
	}
}

func (o *Offloader) removeDomainLocked(domain string) {
	old, ok := o.domains[domain]
	if !ok {
		return
	}
	for ip := range old.ips {
		owners := o.owners[ip]
		delete(owners, domain)
		if len(owners) == 0 {
			delete(o.owners, ip)
		}
	}
	delete(o.domains, domain)
}

func (o *Offloader) reconcileLocked() {
	directNext := make(map[netip.Addr]struct{}, len(o.owners))
	proxyNext := make(map[netip.Addr]struct{}, len(o.owners))
	for ip, owners := range o.owners {
		direct := false
		proxy := false
		for _, action := range owners {
			direct = direct || action == Direct
			proxy = proxy || action == Proxy
		}
		if proxy {
			proxyNext[ip] = struct{}{}
		} else if direct {
			directNext[ip] = struct{}{}
		}
	}
	if !sameAddressSet(o.desiredDirect, directNext) || !sameAddressSet(o.desiredProxy, proxyNext) {
		o.desiredDirect = directNext
		o.desiredProxy = proxyNext
		o.dirty = true
	}
}

func (o *Offloader) flushLocked() error {
	if !o.dirty || o.writer == nil {
		return nil
	}
	diff := DestinationSets{
		DirectAdd: difference(o.desiredDirect, o.appliedDirect), DirectRemove: difference(o.appliedDirect, o.desiredDirect),
		ProxyAdd: difference(o.desiredProxy, o.appliedProxy), ProxyRemove: difference(o.appliedProxy, o.desiredProxy),
	}
	if err := o.writer.Apply(diff); err != nil {
		return err // applied remains untouched: the complete diff is retryable
	}
	o.appliedDirect = cloneAddressSet(o.desiredDirect)
	o.appliedProxy = cloneAddressSet(o.desiredProxy)
	o.dirty = false
	return nil
}

func offloadableAddress(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	// RFC 2544 benchmarking range is Mihomo's default Fake-IP pool.
	return !netip.MustParsePrefix("198.18.0.0/15").Contains(ip)
}

func difference(left, right map[netip.Addr]struct{}) []netip.Addr {
	result := make([]netip.Addr, 0)
	for ip := range left {
		if _, exists := right[ip]; !exists {
			result = append(result, ip)
		}
	}
	return result
}

func cloneAddressSet(source map[netip.Addr]struct{}) map[netip.Addr]struct{} {
	clone := make(map[netip.Addr]struct{}, len(source))
	for ip := range source {
		clone[ip] = struct{}{}
	}
	return clone
}

func sameAddressSet(left, right map[netip.Addr]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for ip := range left {
		if _, exists := right[ip]; !exists {
			return false
		}
	}
	return true
}
