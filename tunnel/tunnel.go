package tunnel

import (
	"sync"
	"time"

	InboundAdapter "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/common/observable"
	cfg "github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"

	"gopkg.in/eapache/channels.v1"
)

var (
	tunnel *Tunnel
	once   sync.Once
)

// Tunnel handle proxy socket and HTTP/SOCKS socket
type Tunnel struct {
	queue      *channels.InfiniteChannel
	rules      []C.Rule
	proxies    map[string]C.Proxy
	configLock *sync.RWMutex
	traffic    *C.Traffic

	// Outbound Rule
	mode cfg.Mode

	// Log
	logCh      chan interface{}
	observable *observable.Observable
	logLevel   C.LogLevel
}

// Add request to queue
func (t *Tunnel) Add(req C.ServerAdapter) {
	t.queue.In() <- req
}

// Traffic return traffic of all connections
func (t *Tunnel) Traffic() *C.Traffic {
	return t.traffic
}

// Log return clash log stream
func (t *Tunnel) Log() *observable.Observable {
	return t.observable
}

func (t *Tunnel) configMonitor(signal chan<- struct{}) {
	sub := cfg.Instance().Subscribe()
	signal <- struct{}{}
	for elm := range sub {
		event := elm.(*cfg.Event)
		switch event.Type {
		case "proxies":
			proxies := event.Payload.(map[string]C.Proxy)
			t.configLock.Lock()
			t.proxies = proxies
			t.configLock.Unlock()
		case "rules":
			rules := event.Payload.([]C.Rule)
			t.configLock.Lock()
			t.rules = rules
			t.configLock.Unlock()
		case "mode":
			t.mode = event.Payload.(cfg.Mode)
		case "log-level":
			t.logLevel = event.Payload.(C.LogLevel)
		}
	}
}

func (t *Tunnel) process() {
	queue := t.queue.Out()
	for {
		elm := <-queue
		conn := elm.(C.ServerAdapter)
		go t.handleConn(conn)
	}
}

func (t *Tunnel) handleConn(localConn C.ServerAdapter) {
	defer localConn.Close()
	metadata := localConn.Metadata()

	var proxy C.Proxy
	switch t.mode {
	case cfg.Direct:
		proxy = t.proxies["DIRECT"]
	case cfg.Global:
		proxy = t.proxies["GLOBAL"]
	// Rule
	default:
		proxy = t.match(metadata)
	}
	remoConn, err := proxy.Generator(metadata)
	if err != nil {
		t.logCh <- newLog(C.WARNING, "Proxy connect error: %s", err.Error())
		return
	}
	defer remoConn.Close()

	switch adapter := localConn.(type) {
	case *InboundAdapter.HTTPAdapter:
		t.handleHTTP(adapter, remoConn)
	case *InboundAdapter.SocketAdapter:
		t.handleSOCKS(adapter, remoConn)
	}
}

func (t *Tunnel) match(metadata *C.Metadata) C.Proxy {
	t.configLock.RLock()
	defer t.configLock.RUnlock()

	for _, rule := range t.rules {
		if rule.IsMatch(metadata) {
			a, ok := t.proxies[rule.Adapter()]
			if !ok {
				continue
			}
			t.logCh <- newLog(C.INFO, "%v match %s using %s", metadata.String(), rule.RuleType().String(), rule.Adapter())
			return a
		}
	}
	t.logCh <- newLog(C.INFO, "%v doesn't match any rule using DIRECT", metadata.String())
	return t.proxies["DIRECT"]
}

// Run initial task
func (t *Tunnel) Run() {
	go t.process()
	go t.subscribeLogs()
	signal := make(chan struct{})
	go t.configMonitor(signal)
	<-signal
}

func newTunnel() *Tunnel {
	logCh := make(chan interface{})
	return &Tunnel{
		queue:      channels.NewInfiniteChannel(),
		proxies:    make(map[string]C.Proxy),
		observable: observable.NewObservable(logCh),
		logCh:      logCh,
		configLock: &sync.RWMutex{},
		traffic:    C.NewTraffic(time.Second),
		mode:       cfg.Rule,
		logLevel:   C.INFO,
	}
}

// Instance return singleton instance of Tunnel
func Instance() *Tunnel {
	once.Do(func() {
		tunnel = newTunnel()
	})
	return tunnel
}
