package fakeip

import (
	"errors"
	"math/bits"
	"net/netip"
	"sync"
	_ "unsafe"

	"github.com/Dreamacro/clash/component/profile/cachefile"
	"github.com/Dreamacro/clash/component/trie"
)

//go:linkname beUint64 net/netip.beUint64
func beUint64(b []byte) uint64

//go:linkname bePutUint64 net/netip.bePutUint64
func bePutUint64(b []byte, v uint64)

type uint128 struct {
	hi uint64
	lo uint64
}

type store interface {
	GetByHost(host string) (netip.Addr, bool)
	PutByHost(host string, ip netip.Addr)
	GetByIP(ip netip.Addr) (string, bool)
	PutByIP(ip netip.Addr, host string)
	DelByIP(ip netip.Addr)
	Exist(ip netip.Addr) bool
	CloneTo(store)
	FlushFakeIP() error
}

// Pool is a implementation about fake ip generator without storage
type Pool struct {
	gateway netip.Addr
	first   netip.Addr
	last    netip.Addr
	offset  netip.Addr
	cycle   bool
	mux     sync.Mutex
	host    *trie.DomainTrie[bool]
	ipnet   *netip.Prefix
	store   store
}

// Lookup return a fake ip with host
func (p *Pool) Lookup(host string) netip.Addr {
	p.mux.Lock()
	defer p.mux.Unlock()
	if ip, exist := p.store.GetByHost(host); exist {
		return ip
	}

	ip := p.get(host)
	p.store.PutByHost(host, ip)
	return ip
}

// LookBack return host with the fake ip
func (p *Pool) LookBack(ip netip.Addr) (string, bool) {
	p.mux.Lock()
	defer p.mux.Unlock()

	return p.store.GetByIP(ip)
}

// ShouldSkipped return if domain should be skipped
func (p *Pool) ShouldSkipped(domain string) bool {
	if p.host == nil {
		return false
	}
	return p.host.Search(domain) != nil
}

// Exist returns if given ip exists in fake-ip pool
func (p *Pool) Exist(ip netip.Addr) bool {
	p.mux.Lock()
	defer p.mux.Unlock()

	return p.store.Exist(ip)
}

// Gateway return gateway ip
func (p *Pool) Gateway() netip.Addr {
	return p.gateway
}

// Broadcast return the last ip
func (p *Pool) Broadcast() netip.Addr {
	return p.last
}

// IPNet return raw ipnet
func (p *Pool) IPNet() *netip.Prefix {
	return p.ipnet
}

// CloneFrom clone cache from old pool
func (p *Pool) CloneFrom(o *Pool) {
	o.store.CloneTo(p.store)
}

func (p *Pool) get(host string) netip.Addr {
	p.offset = p.offset.Next()

	if !p.offset.Less(p.last) {
		p.cycle = true
		p.offset = p.first
	}

	if p.cycle {
		p.store.DelByIP(p.offset)
	}

	p.store.PutByIP(p.offset, host)
	return p.offset
}

func (p *Pool) FlushFakeIP() error {
	return p.store.FlushFakeIP()
}

type Options struct {
	IPNet *netip.Prefix
	Host  *trie.DomainTrie[bool]

	// Size sets the maximum number of entries in memory
	// and does not work if Persistence is true
	Size int

	// Persistence will save the data to disk.
	// Size will not work and record will be fully stored.
	Persistence bool
}

// New return Pool instance
func New(options Options) (*Pool, error) {
	var (
		hostAddr = options.IPNet.Masked().Addr()
		gateway  = hostAddr.Next()
		first    = gateway.Next().Next()
		last     = add(hostAddr, 1<<uint64(hostAddr.BitLen()-options.IPNet.Bits())-1)
	)

	if !options.IPNet.IsValid() || !first.Less(last) || !options.IPNet.Contains(last) {
		return nil, errors.New("ipnet don't have valid ip")
	}

	pool := &Pool{
		gateway: gateway,
		first:   first,
		last:    last,
		offset:  first.Prev(),
		cycle:   false,
		host:    options.Host,
		ipnet:   options.IPNet,
	}
	if options.Persistence {
		pool.store = &cachefileStore{
			cache: cachefile.Cache(),
		}
	} else {
		pool.store = newMemoryStore(options.Size)
	}

	return pool, nil
}

// add returns addr + n.
func add(addr netip.Addr, n uint64) netip.Addr {
	buf := addr.As16()

	u := uint128{
		beUint64(buf[:8]),
		beUint64(buf[8:]),
	}

	lo, carry := bits.Add64(u.lo, n, 0)

	u.hi = u.hi + carry
	u.lo = lo

	bePutUint64(buf[:8], u.hi)
	bePutUint64(buf[8:], u.lo)

	a := netip.AddrFrom16(buf)

	if addr.Is4() {
		return a.Unmap()
	}

	return a
}
