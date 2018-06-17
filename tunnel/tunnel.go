package tunnel

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

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
	traffic    *C.Traffic
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
	groupsConfig := cfg.Section("Proxy Group")

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
			ss, err := adapters.NewShadowSocks(key.Name(), ssURL, t.traffic)
			if err != nil {
				return err
			}
			proxys[key.Name()] = ss
		}
	}

	// init proxy
	proxys["DIRECT"] = adapters.NewDirect(t.traffic)
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

	// parse proxy groups
	for _, key := range groupsConfig.Keys() {
		rule := strings.Split(key.Value(), ",")
		if len(rule) < 4 {
			continue
		}
		rule = trimArr(rule)
		switch rule[0] {
		case "url-test":
			proxyNames := rule[1 : len(rule)-2]
			delay, _ := strconv.Atoi(rule[len(rule)-1])
			url := rule[len(rule)-2]
			var ps []C.Proxy
			for _, name := range proxyNames {
				if p, ok := proxys[name]; ok {
					ps = append(ps, p)
				}
			}

			adapter, err := adapters.NewURLTest(key.Name(), ps, url, time.Duration(delay)*time.Second)
			if err != nil {
				return fmt.Errorf("Config error: %s", err.Error())
			}
			proxys[key.Name()] = adapter
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
	t.logCh <- newLog(INFO, "%v doesn't match any rule using DIRECT", addr.String())
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
		traffic:    C.NewTraffic(time.Second),
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
