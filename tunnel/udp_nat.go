package tunnel

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
)

type udpNATTargetKey struct {
	origin M.Socksaddr
	target M.Socksaddr
}

type udpNATOriginKey struct {
	origin M.Socksaddr
	domain string
}

type udpNATOrigins map[udpNATOriginKey]M.Socksaddr

type udpNATDomain struct {
	first M.Socksaddr
	ports map[uint16]udpNATOrigins
}

type udpNATLearned struct {
	origin     M.Socksaddr
	candidates int
}

// A session has one PacketConn. Keep its address history separate from the
// sender so replies can be restored while the next packet is being prepared.
type udpNAT struct {
	mu sync.Mutex

	remoteCache  map[udpNATTargetKey]M.Socksaddr
	localCache   map[M.Socksaddr]M.Socksaddr
	knownIPs     map[netip.Addr]M.Socksaddr
	directAccess map[netip.Addr]struct{}
	domains      map[string]*udpNATDomain
	ports        map[uint16]udpNATOrigins
	origins      udpNATOrigins
	learned      map[netip.AddrPort]udpNATLearned
	firstOrigin  M.Socksaddr

	initialized bool
	bound       bool
	boundOrigin M.Socksaddr
}

func newUDPNAT() *udpNAT {
	return &udpNAT{
		remoteCache:  make(map[udpNATTargetKey]M.Socksaddr),
		localCache:   make(map[M.Socksaddr]M.Socksaddr),
		knownIPs:     make(map[netip.Addr]M.Socksaddr),
		directAccess: make(map[netip.Addr]struct{}),
		domains:      make(map[string]*udpNATDomain),
		ports:        make(map[uint16]udpNATOrigins),
		origins:      make(udpNATOrigins),
		learned:      make(map[netip.AddrPort]udpNATLearned),
	}
}

// Only lookup keys are normalized; the wire spelling of a domain and the
// client's original address must survive caching and reply restoration.
func udpNATAddressKey(address M.Socksaddr) M.Socksaddr {
	address.Addr = address.Addr.Unmap()
	address.Fqdn = strings.ToLower(strings.TrimSuffix(address.Fqdn, "."))
	return address
}

func udpNATOriginAddress(address M.Socksaddr) M.Socksaddr {
	address.Addr = address.Addr.Unmap()
	address.Port = 0
	return address
}

func (n *udpNAT) register(origin, target, prepared M.Socksaddr, direct bool, capabilities C.UDPCapabilities) {
	origin.Addr = origin.Addr.Unmap()
	prepared.Addr = prepared.Addr.Unmap()
	originAddress := udpNATOriginAddress(origin)
	originKey := udpNATAddressKey(originAddress)

	n.mu.Lock()
	defer n.mu.Unlock()

	if direct && origin.IsIP() {
		n.directAccess[origin.Addr] = struct{}{}
	}
	if prepared.IsIP() {
		// The old sender cached a resolved IP without the destination port.
		// Retain that lifetime so another port cannot trigger another lookup.
		if _, loaded := n.localCache[originKey]; !loaded {
			n.localCache[originKey] = prepared
		}
	} else {
		key := udpNATTargetKey{udpNATAddressKey(origin), udpNATAddressKey(target)}
		if _, loaded := n.remoteCache[key]; !loaded {
			n.remoteCache[key] = prepared
		}
	}

	if n.initialized && n.bound {
		// Native single-target protocols keep their existing second-target
		// behavior; a later write must not change the reply's bound origin.
		return
	}
	if !n.initialized {
		n.initialized = true
		n.bound = capabilities.Reply == C.UDPReplyBoundDestination
		if n.bound && prepared.IsFqdn() {
			n.boundOrigin = originAddress
		}
	}

	if prepared.IsIP() {
		// Local resolution historically restored only IP origins. A SOCKS
		// domain origin must not start turning local IP replies into FQDNs.
		if origin.IsIP() {
			if _, loaded := n.knownIPs[prepared.Addr]; !loaded {
				n.knownIPs[prepared.Addr] = originAddress
			}
		}
		return
	}

	domain := udpNATAddressKey(prepared).Fqdn
	key := udpNATOriginKey{originKey, domain}
	if !n.firstOrigin.IsValid() {
		n.firstOrigin = originAddress
	}
	if _, loaded := n.origins[key]; !loaded {
		n.origins[key] = originAddress
	}
	if n.ports[prepared.Port] == nil {
		n.ports[prepared.Port] = make(udpNATOrigins)
	}
	n.ports[prepared.Port][key] = originAddress

	entry := n.domains[domain]
	if entry == nil {
		entry = &udpNATDomain{
			first: originAddress,
			ports: make(map[uint16]udpNATOrigins),
		}
		n.domains[domain] = entry
	}
	if entry.ports[prepared.Port] == nil {
		entry.ports[prepared.Port] = make(udpNATOrigins)
	}
	entry.ports[prepared.Port][key] = originAddress
}

func (n *udpNAT) cached(origin, target M.Socksaddr) (M.Socksaddr, bool) {
	key := udpNATTargetKey{udpNATAddressKey(origin), udpNATAddressKey(target)}
	originKey := udpNATAddressKey(udpNATOriginAddress(origin))
	n.mu.Lock()
	defer n.mu.Unlock()
	if prepared, loaded := n.remoteCache[key]; loaded {
		return prepared, true
	}
	prepared, loaded := n.localCache[originKey]
	if loaded {
		prepared.Port = target.Port
	}
	return prepared, loaded
}

func udpNATWithPort(origin M.Socksaddr, port uint16) M.Socksaddr {
	origin.Port = port
	return origin
}

func udpNATOnlyOrigin(origins udpNATOrigins) M.Socksaddr {
	for _, origin := range origins {
		return origin
	}
	return M.Socksaddr{}
}

func (n *udpNAT) restore(from M.Socksaddr) (M.Socksaddr, error) {
	if !from.IsValid() || from.IsIP() && from.Fqdn != "" {
		return M.Socksaddr{}, fmt.Errorf("invalid UDP reply address: %#v", from)
	}
	from.Addr = from.Addr.Unmap()
	n.mu.Lock()
	defer n.mu.Unlock()

	if from.IsIP() {
		if _, direct := n.directAccess[from.Addr]; direct {
			return from, nil
		}
	}
	if n.boundOrigin.IsValid() {
		return udpNATWithPort(n.boundOrigin, from.Port), nil
	}
	if from.IsFqdn() {
		entry := n.domains[udpNATAddressKey(from).Fqdn]
		if entry == nil {
			return M.Socksaddr{}, fmt.Errorf("unknown UDP reply domain: %s", from.Fqdn)
		}
		if matches := entry.ports[from.Port]; len(matches) == 1 {
			return udpNATWithPort(udpNATOnlyOrigin(matches), from.Port), nil
		}
		// The protocol cannot distinguish several origins for one domain.
		// Use that domain's first origin, not the session's first origin;
		// destination-dependent mapping is available for exact isolation.
		return udpNATWithPort(entry.first, from.Port), nil
	}
	if origin, known := n.knownIPs[from.Addr]; known {
		return udpNATWithPort(origin, from.Port), nil
	}
	if n.bound || len(n.origins) == 0 {
		return from, nil
	}

	peer := netip.AddrPortFrom(from.Addr, from.Port)
	matches := n.ports[from.Port]
	if learned, found := n.learned[peer]; found {
		if learned.candidates == len(matches) {
			return udpNATWithPort(learned.origin, from.Port), nil
		}
		// Candidate sets only grow during a session. A formerly unique port
		// cannot keep an old inferred binding after another origin joins it.
		delete(n.learned, peer)
	}
	if len(n.origins) == 1 {
		return udpNATWithPort(n.firstOrigin, from.Port), nil
	}
	switch len(matches) {
	case 0:
		return from, nil
	case 1:
		origin := udpNATOnlyOrigin(matches)
		n.learned[peer] = udpNATLearned{origin: origin, candidates: len(matches)}
		return udpNATWithPort(origin, from.Port), nil
	default:
		return udpNATWithPort(n.firstOrigin, from.Port), nil
	}
}
