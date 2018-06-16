package tunnel

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/adapters"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/observable"
	R "github.com/Dreamacro/clash/rules"

	"gopkg.in/eapache/channels.v1"
)

var (
	tunnel *Tunnel
	once   sync.Once
)

type Tunnel struct {
	queue      *channels.InfiniteChannel
	rules      []C.Rule
	proxys     map[string]C.Proxy
	observable *observable.Observable
	logCh      chan interface{}
	configLock *sync.RWMutex
}

func (t *Tunnel) Add(req C.ServerAdapter) {
	t.queue.In() <- req
}

func (t *Tunnel) UpdateConfig() (err error) {
	cfg, err := C.GetConfig()
	if err != nil {
		return
	}

	// clear proxys and rules
	proxys := make(map[string]C.Proxy)
	rules := []C.Rule{}

	proxysConfig := cfg.Section("Proxy")
	rulesConfig := cfg.Section("Rule")

	// parse proxy
	for _, key := range proxysConfig.Keys() {
		proxy := strings.Split(key.Value(), ",")
		if len(proxy) == 0 {
			continue
		}
		proxy = trimArr(proxy)
		switch proxy[0] {
		// ss, server, port, cipter, password
		case "ss":
			if len(proxy) < 5 {
				continue
			}
			ssURL := fmt.Sprintf("ss://%s:%s@%s:%s", proxy[3], proxy[4], proxy[1], proxy[2])
			ss, err := adapters.NewShadowSocks(ssURL)
			if err != nil {
				return err
			}
			proxys[key.Name()] = ss
		}
	}

	// init proxy
	proxys["DIRECT"] = adapters.NewDirect()
	proxys["REJECT"] = adapters.NewReject()

	// parse rules
	for _, key := range rulesConfig.Keys() {
		rule := strings.Split(key.Name(), ",")
		if len(rule) < 3 {
			continue
		}
		rule = trimArr(rule)
		switch rule[0] {
		case "DOMAIN-SUFFIX":
			rules = append(rules, R.NewDomainSuffix(rule[1], rule[2]))
		case "DOMAIN-KEYWORD":
			rules = append(rules, R.NewDomainKeyword(rule[1], rule[2]))
		case "GEOIP":
			rules = append(rules, R.NewGEOIP(rule[1], rule[2]))
		case "IP-CIDR", "IP-CIDR6":
			rules = append(rules, R.NewIPCIDR(rule[1], rule[2]))
		case "FINAL":
			rules = append(rules, R.NewFinal(rule[2]))
		}
	}

	t.configLock.Lock()
	defer t.configLock.Unlock()

	t.proxys = proxys
	t.rules = rules

	return nil
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
	addr := localConn.Addr()
	proxy := t.match(addr)
	remoConn, err := proxy.Generator(addr)
	if err != nil {
		t.logCh <- newLog(WARNING, "Proxy connect error: %s", err.Error())
		return
	}
	defer remoConn.Close()

	localConn.Connect(remoConn)
}

func (t *Tunnel) match(addr *C.Addr) C.Proxy {
	t.configLock.RLock()
	defer t.configLock.RUnlock()

	for _, rule := range t.rules {
		if rule.IsMatch(addr) {
			a, ok := t.proxys[rule.Adapter()]
			if !ok {
				continue
			}
			t.logCh <- newLog(INFO, "%v match %d using %s", addr.String(), rule.RuleType(), rule.Adapter())
			return a
		}
	}
	t.logCh <- newLog(INFO, "don't find, direct")
	return t.proxys["DIRECT"]
}

func newTunnel() *Tunnel {
	logCh := make(chan interface{})
	tunnel := &Tunnel{
		queue:      channels.NewInfiniteChannel(),
		proxys:     make(map[string]C.Proxy),
		observable: observable.NewObservable(logCh),
		logCh:      logCh,
		configLock: &sync.RWMutex{},
	}
	go tunnel.process()
	go tunnel.subscribeLogs()
	return tunnel
}

func GetInstance() *Tunnel {
	once.Do(func() {
		tunnel = newTunnel()
	})
	return tunnel
}
