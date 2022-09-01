package fakeip

import (
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/profile/cachefile"
	"github.com/Dreamacro/clash/component/trie"
)

type store interface {
	GetByHost(host string) (net.IP, bool)
	PutByHost(host string, ip net.IP)
	GetByIP(ip net.IP) (string, bool)
	PutByIP(ip net.IP, host string)
	DelByIP(ip net.IP)
	Exist(ip net.IP) bool
	CloneTo(store)
}

// Pool is an implementation about fake ip generator without storage
type Pool struct {
	max     uint32
	min     uint32
	gateway uint32
	offset  uint32
	mux     sync.Mutex
	host    *trie.DomainTrie
	ipnet   *net.IPNet
	store   store
}

// Lookup return a fake ip with host
func (p *Pool) Lookup(host string) net.IP {
	p.mux.Lock()
	defer p.mux.Unlock()

	// RFC4343: DNS Case Insensitive, we SHOULD return result with all cases.
	host = strings.ToLower(host)
	if ip, exist := p.store.GetByHost(host); exist {
		return ip
	}

	ip := p.get(host)
	p.store.PutByHost(host, ip)
	return ip
}

// LookBack return host with the fake ip
func (p *Pool) LookBack(ip net.IP) (string, bool) {
	p.mux.Lock()
	defer p.mux.Unlock()

	if ip = ip.To4(); ip == nil {
		return "", false
	}

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
func (p *Pool) Exist(ip net.IP) bool {
	p.mux.Lock()
	defer p.mux.Unlock()

	if ip = ip.To4(); ip == nil {
		return false
	}

	return p.store.Exist(ip)
}

// Gateway return gateway ip
func (p *Pool) Gateway() net.IP {
	return uintToIP(p.gateway)
}

// IPNet return raw ipnet
func (p *Pool) IPNet() *net.IPNet {
	return p.ipnet
}

// CloneFrom clone cache from old pool
func (p *Pool) CloneFrom(o *Pool) {
	o.store.CloneTo(p.store)
}

func (p *Pool) get(host string) net.IP {
	current := p.offset
	for {
		ip := uintToIP(p.min + p.offset)
		if !p.store.Exist(ip) {
			break
		}

		p.offset = (p.offset + 1) % (p.max - p.min)
		// Avoid infinite loops
		if p.offset == current {
			p.offset = (p.offset + 1) % (p.max - p.min)
			ip := uintToIP(p.min + p.offset)
			p.store.DelByIP(ip)
			break
		}
	}
	ip := uintToIP(p.min + p.offset)
	p.store.PutByIP(ip, host)
	return ip
}

func ipToUint(ip net.IP) uint32 {
	v := uint32(ip[0]) << 24
	v += uint32(ip[1]) << 16
	v += uint32(ip[2]) << 8
	v += uint32(ip[3])
	return v
}

func uintToIP(v uint32) net.IP {
	return net.IP{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

type Options struct {
	IPNet *net.IPNet
	Host  *trie.DomainTrie

	// Size sets the maximum number of entries in memory
	// and does not work if Persistence is true
	Size int

	// Persistence will save the data to disk.
	// Size will not work and record will be fully stored.
	Persistence bool
}

// New return Pool instance
func New(options Options) (*Pool, error) {
	min := ipToUint(options.IPNet.IP) + 2

	ones, bits := options.IPNet.Mask.Size()
	total := 1<<uint(bits-ones) - 2

	if total <= 0 {
		return nil, errors.New("ipnet don't have valid ip")
	}

	max := min + uint32(total) - 1
	pool := &Pool{
		min:     min,
		max:     max,
		gateway: min - 1,
		host:    options.Host,
		ipnet:   options.IPNet,
	}
	if options.Persistence {
		pool.store = &cachefileStore{
			cache: cachefile.Cache(),
		}
	} else {
		pool.store = &memoryStore{
			cache: cache.New(cache.WithSize(options.Size * 2)),
		}
	}

	return pool, nil
}
