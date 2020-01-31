package tunnel

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/adapters/provider"
	"github.com/Dreamacro/clash/component/nat"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/log"

	channels "gopkg.in/eapache/channels.v1"
)

var (
	tunnel *Tunnel
	once   sync.Once

	// default timeout for UDP session
	udpTimeout = 60 * time.Second
)

// Tunnel handle relay inbound proxy and outbound proxy
type Tunnel struct {
	tcpQueue  *channels.InfiniteChannel
	udpQueue  *channels.InfiniteChannel
	natTable  *nat.Table
	rules     []C.Rule
	proxies   map[string]C.Proxy
	providers map[string]provider.ProxyProvider
	configMux sync.RWMutex

	// experimental features
	ignoreResolveFail bool

	// Outbound Rule
	mode Mode
}

// Add request to queue
func (t *Tunnel) Add(req C.ServerAdapter) {
	t.tcpQueue.In() <- req
}

// AddPacket add udp Packet to queue
func (t *Tunnel) AddPacket(packet *inbound.PacketAdapter) {
	t.udpQueue.In() <- packet
}

// Rules return all rules
func (t *Tunnel) Rules() []C.Rule {
	return t.rules
}

// UpdateRules handle update rules
func (t *Tunnel) UpdateRules(rules []C.Rule) {
	t.configMux.Lock()
	t.rules = rules
	t.configMux.Unlock()
}

// Proxies return all proxies
func (t *Tunnel) Proxies() map[string]C.Proxy {
	return t.proxies
}

// Providers return all compatible providers
func (t *Tunnel) Providers() map[string]provider.ProxyProvider {
	return t.providers
}

// UpdateProxies handle update proxies
func (t *Tunnel) UpdateProxies(proxies map[string]C.Proxy, providers map[string]provider.ProxyProvider) {
	t.configMux.Lock()
	t.proxies = proxies
	t.providers = providers
	t.configMux.Unlock()
}

// UpdateExperimental handle update experimental config
func (t *Tunnel) UpdateExperimental(ignoreResolveFail bool) {
	t.configMux.Lock()
	t.ignoreResolveFail = ignoreResolveFail
	t.configMux.Unlock()
}

// Mode return current mode
func (t *Tunnel) Mode() Mode {
	return t.mode
}

// SetMode change the mode of tunnel
func (t *Tunnel) SetMode(mode Mode) {
	t.mode = mode
}

// processUDP starts a loop to handle udp packet
func (t *Tunnel) processUDP() {
	queue := t.udpQueue.Out()
	for elm := range queue {
		conn := elm.(*inbound.PacketAdapter)
		t.handleUDPConn(conn)
	}
}

func (t *Tunnel) process() {
	numUDPWorkers := 4
	if runtime.NumCPU() > numUDPWorkers {
		numUDPWorkers = runtime.NumCPU()
	}
	for i := 0; i < numUDPWorkers; i++ {
		go t.processUDP()
	}

	queue := t.tcpQueue.Out()
	for elm := range queue {
		conn := elm.(C.ServerAdapter)
		go t.handleTCPConn(conn)
	}
}

func (t *Tunnel) resolveIP(host string) (net.IP, error) {
	return dns.ResolveIP(host)
}

func (t *Tunnel) needLookupIP(metadata *C.Metadata) bool {
	return dns.DefaultResolver != nil && (dns.DefaultResolver.IsMapping() || dns.DefaultResolver.FakeIPEnabled()) && metadata.Host == "" && metadata.DstIP != nil
}

func (t *Tunnel) resolveMetadata(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	// handle host equal IP string
	if ip := net.ParseIP(metadata.Host); ip != nil {
		metadata.DstIP = ip
	}

	// preprocess enhanced-mode metadata
	if t.needLookupIP(metadata) {
		host, exist := dns.DefaultResolver.IPToHost(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.AddrType = C.AtypDomainName
			if dns.DefaultResolver.FakeIPEnabled() {
				metadata.DstIP = nil
			}
		}
	}

	var proxy C.Proxy
	var rule C.Rule
	switch t.mode {
	case Direct:
		proxy = t.proxies["DIRECT"]
	case Global:
		proxy = t.proxies["GLOBAL"]
	// Rule
	default:
		var err error
		proxy, rule, err = t.match(metadata)
		if err != nil {
			return nil, nil, err
		}
	}
	return proxy, rule, nil
}

func (t *Tunnel) handleUDPConn(packet *inbound.PacketAdapter) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	key := packet.LocalAddr().String()

	pc := t.natTable.Get(key)
	addr := metadata.UDPAddr()
	if pc != nil {
		t.handleUDPToRemote(packet, pc, addr)
		return
	}

	lockKey := key + "-lock"
	wg, loaded := t.natTable.GetOrCreateLock(lockKey)

	go func() {
		if !loaded {
			wg.Add(1)
			proxy, rule, err := t.resolveMetadata(metadata)
			if err != nil {
				log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
				t.natTable.Delete(lockKey)
				wg.Done()
				return
			}

			rawPc, err := proxy.DialUDP(metadata)
			if err != nil {
				log.Warnln("[UDP] dial %s error: %s", proxy.Name(), err.Error())
				t.natTable.Delete(lockKey)
				wg.Done()
				return
			}
			pc = newUDPTracker(rawPc, DefaultManager, metadata, rule)

			switch true {
			case rule != nil:
				log.Infoln("[UDP] %s --> %v match %s using %s", metadata.SourceAddress(), metadata.String(), rule.RuleType().String(), rawPc.Chains().String())
			case t.mode == Global:
				log.Infoln("[UDP] %s --> %v using GLOBAL", metadata.SourceAddress(), metadata.String())
			case t.mode == Direct:
				log.Infoln("[UDP] %s --> %v using DIRECT", metadata.SourceAddress(), metadata.String())
			default:
				log.Infoln("[UDP] %s --> %v doesn't match any rule using DIRECT", metadata.SourceAddress(), metadata.String())
			}

			t.natTable.Set(key, pc)
			t.natTable.Delete(lockKey)
			wg.Done()
			go t.handleUDPToLocal(packet.UDPPacket, pc, key)
		}

		wg.Wait()
		pc := t.natTable.Get(key)
		if pc != nil {
			t.handleUDPToRemote(packet, pc, addr)
		}
	}()
}

func (t *Tunnel) handleTCPConn(localConn C.ServerAdapter) {
	defer localConn.Close()

	metadata := localConn.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	proxy, rule, err := t.resolveMetadata(metadata)
	if err != nil {
		log.Warnln("Parse metadata failed: %v", err)
		return
	}

	remoteConn, err := proxy.Dial(metadata)
	if err != nil {
		log.Warnln("dial %s error: %s", proxy.Name(), err.Error())
		return
	}
	remoteConn = newTCPTracker(remoteConn, DefaultManager, metadata, rule)
	defer remoteConn.Close()

	switch true {
	case rule != nil:
		log.Infoln("[TCP] %s --> %v match %s using %s", metadata.SourceAddress(), metadata.String(), rule.RuleType().String(), remoteConn.Chains().String())
	case t.mode == Global:
		log.Infoln("[TCP] %s --> %v using GLOBAL", metadata.SourceAddress(), metadata.String())
	case t.mode == Direct:
		log.Infoln("[TCP] %s --> %v using DIRECT", metadata.SourceAddress(), metadata.String())
	default:
		log.Infoln("[TCP] %s --> %v doesn't match any rule using DIRECT", metadata.SourceAddress(), metadata.String())
	}

	switch adapter := localConn.(type) {
	case *inbound.HTTPAdapter:
		t.handleHTTP(adapter, remoteConn)
	case *inbound.SocketAdapter:
		t.handleSocket(adapter, remoteConn)
	}
}

func (t *Tunnel) shouldResolveIP(rule C.Rule, metadata *C.Metadata) bool {
	return !rule.NoResolveIP() && metadata.Host != "" && metadata.DstIP == nil
}

func (t *Tunnel) match(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	t.configMux.RLock()
	defer t.configMux.RUnlock()

	var resolved bool

	if node := dns.DefaultHosts.Search(metadata.Host); node != nil {
		ip := node.Data.(net.IP)
		metadata.DstIP = ip
		resolved = true
	}

	for _, rule := range t.rules {
		if !resolved && t.shouldResolveIP(rule, metadata) {
			ip, err := t.resolveIP(metadata.Host)
			if err != nil {
				if !t.ignoreResolveFail {
					return nil, nil, fmt.Errorf("[DNS] resolve %s error: %s", metadata.Host, err.Error())
				}
				log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
			} else {
				log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
				metadata.DstIP = ip
			}
			resolved = true
		}

		if rule.Match(metadata) {
			adapter, ok := t.proxies[rule.Adapter()]
			if !ok {
				continue
			}

			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				log.Debugln("%v UDP is not supported", adapter.Name())
				continue
			}
			return adapter, rule, nil
		}
	}
	return t.proxies["DIRECT"], nil, nil
}

func newTunnel() *Tunnel {
	return &Tunnel{
		tcpQueue: channels.NewInfiniteChannel(),
		udpQueue: channels.NewInfiniteChannel(),
		natTable: nat.New(),
		proxies:  make(map[string]C.Proxy),
		mode:     Rule,
	}
}

// Instance return singleton instance of Tunnel
func Instance() *Tunnel {
	once.Do(func() {
		tunnel = newTunnel()
		go tunnel.process()
	})
	return tunnel
}
