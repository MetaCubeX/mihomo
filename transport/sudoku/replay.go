package sudoku

import (
	"sync"
	"time"
)

var handshakeReplayTTL = 60 * time.Second

type nonceSet struct {
	mu         sync.Mutex
	m          map[[kipHelloNonceSize]byte]time.Time
	maxEntries int
	lastPrune  time.Time
}

func newNonceSet(maxEntries int) *nonceSet {
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &nonceSet{
		m:          make(map[[kipHelloNonceSize]byte]time.Time),
		maxEntries: maxEntries,
	}
}

func (s *nonceSet) allow(nonce [kipHelloNonceSize]byte, now time.Time, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ttl <= 0 {
		ttl = 60 * time.Second
	}

	if now.Sub(s.lastPrune) > ttl/2 || len(s.m) > s.maxEntries {
		for k, exp := range s.m {
			if !now.Before(exp) {
				delete(s.m, k)
			}
		}
		s.lastPrune = now
		for len(s.m) > s.maxEntries {
			for k := range s.m {
				delete(s.m, k)
				break
			}
		}
	}

	if exp, ok := s.m[nonce]; ok && now.Before(exp) {
		return false
	}
	s.m[nonce] = now.Add(ttl)
	return true
}

type handshakeReplayProtector struct {
	users sync.Map // map[userHash string]*nonceSet
}

func (p *handshakeReplayProtector) allow(userHash string, nonce [kipHelloNonceSize]byte, now time.Time) bool {
	if userHash == "" {
		userHash = "_"
	}
	val, _ := p.users.LoadOrStore(userHash, newNonceSet(4096))
	set, ok := val.(*nonceSet)
	if !ok || set == nil {
		set = newNonceSet(4096)
		p.users.Store(userHash, set)
	}
	return set.allow(nonce, now, handshakeReplayTTL)
}

var globalHandshakeReplay = &handshakeReplayProtector{}
