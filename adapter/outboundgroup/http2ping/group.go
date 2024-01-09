package http2ping

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"golang.org/x/exp/maps"
)

var _ PingerGroup = (*http2PingGroup)(nil)

type http2PingGroup struct {
	mu       sync.RWMutex
	pingers  map[string]Pinger
	resolver *dnsResolver
	dieCh    chan struct{}
	config   *Config
	best     atomic.Value
}

func NewHTTP2PingGroup(config *Config) PingerGroup {
	g := &http2PingGroup{
		pingers:  make(map[string]Pinger),
		resolver: newDnsResolver(),
		dieCh:    make(chan struct{}),
		config:   config,
	}
	go g.loop(config.Interval)
	return g
}

func (g *http2PingGroup) SetProxies(proxies []constant.Proxy) {
	g.mu.Lock()
	defer g.mu.Unlock()

	newPingers := make(map[string]Pinger)
	oldPingers := g.pingers
	for _, proxy := range proxies {
		// Some network service providers choose to deceive users by using multiple domain names like
		// `endpoint[1-10].airport.com` to give the illusion of a more diverse list of access points,
		// even though they all resolve to the same IP address.
		//
		// To tackle this issue, we resolve the domain names to their respective IP addresses and use
		// the `ip-port` pair as a key for deduplication purposes.
		key, err := g.resolver.DomainPortToIpPort(proxy.Addr())
		if err != nil {
			log.Errorln("[http2ping] resolve domain error for %s: %v", proxy.Addr(), err)
			continue
		}
		if _, ok := newPingers[key]; ok {
			log.Debugln("[http2ping] duplicate proxy [%s] with addr: %s", proxy.Addr(), key)
			continue
		}
		if _, ok := oldPingers[key]; !ok {
			log.Infoln("[http2ping] add proxy [%s:%s] with addr: %s", proxy.Name(), proxy.Addr(), key)
			newPingers[key] = NewHTTP2Pinger(g.config, proxy)
		} else {
			newPingers[key] = oldPingers[key]
			delete(oldPingers, key)
		}
	}
	for _, deadp := range oldPingers {
		deadp.Close()
	}
	g.pingers = newPingers
}

func (g *http2PingGroup) GetConfig() *Config {
	return g.config
}

func (g *http2PingGroup) GetPingersCopy() map[string]Pinger {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return maps.Clone(g.pingers)
}

func (g *http2PingGroup) loop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-g.dieCh:
			return
		case <-ticker.C:
			var newBest Pinger
			minRtt := uint32(1<<31 - 1)
			for _, p := range g.GetPingersCopy() {
				if rtt := p.GetSmoothRtt(); rtt > 0 && rtt < minRtt {
					minRtt = rtt
					newBest = p
				}
			}
			oldBest := g.loadBest()
			if g.foundBetterProxy(oldBest, newBest) {
				g.best.Store(newBest)
			}
		}
	}
}

func (g *http2PingGroup) GetMinRttProxy(ctx context.Context) constant.Proxy {
	if p := g.loadBest(); p != nil {
		return p.GetProxy()
	}
	return nil
}

func (g *http2PingGroup) Close() error {
	close(g.dieCh)
	return nil
}

func (g *http2PingGroup) loadBest() Pinger {
	if ptr := g.best.Load(); ptr != nil {
		if p, ok := ptr.(Pinger); ok {
			return p
		}
	}
	return nil
}

func (g *http2PingGroup) foundBetterProxy(oldp, newp Pinger) bool {
	if oldp == nil && newp != nil {
		return true
	}
	if oldp == newp || newp == nil {
		return false
	}
	oldRtt := time.Millisecond * time.Duration(oldp.GetSmoothRtt())
	newRtt := time.Millisecond * time.Duration(newp.GetSmoothRtt())
	ok := oldRtt-newRtt > g.config.Tolerance
	if ok {
		log.Debugln("[http2ping] change best route from [%v][rtt: %v] to [%v][rtt: %v]",
			oldp, oldRtt, newp, newRtt)
	}
	return ok
}
