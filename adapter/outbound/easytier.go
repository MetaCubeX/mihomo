//go:build !no_easytier

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/easytier"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	corehost "github.com/easytier/easytier/easytier-go"
	D "github.com/miekg/dns"
)

const (
	easyTierDefaultStateDir = "easytier"
	easyTierInstanceIDFile  = "instance_id"
	easyTierDNSTTL          = 60
	easyTierHealthInterval  = 10 * time.Second
	easyTierHealthTimeout   = 5 * time.Second
	easyTierStartGrace      = 30 * time.Second
	easyTierUnhealthyLimit  = 3
	easyTierMinBackoff      = time.Second
	easyTierMaxBackoff      = 30 * time.Second
)

var errEasyTierClosed = errors.New("easytier outbound closed")

type EasyTier struct {
	*Base
	option     EasyTierOption
	configTOML string
	stateDir   string
	instanceID string
	zone       string
	ctx        context.Context
	cancel     context.CancelFunc
	startMu    sync.Mutex
	closed     bool
	gen        uint64
	backoff    time.Duration
	startErr   error
	mu         sync.Mutex
	host       *corehost.Host
	instance   *corehost.Instance
	unregister func()
}

type EasyTierOption struct {
	BasicOption
	Name                string   `proxy:"name"`
	NetworkName         string   `proxy:"network-name,omitempty"`
	NetworkSecret       string   `proxy:"network-secret,omitempty"`
	Hostname            string   `proxy:"hostname,omitempty"`
	IPv4                string   `proxy:"ipv4,omitempty"`
	DHCP                bool     `proxy:"dhcp,omitempty"`
	Peers               []string `proxy:"peers,omitempty"`
	Listeners           []string `proxy:"listeners,omitempty"`
	NoListener          *bool    `proxy:"no-listener,omitempty"`
	MappedListeners     []string `proxy:"mapped-listeners,omitempty"`
	ExitNodes           []string `proxy:"exit-nodes,omitempty"`
	ProxyNetworks       []string `proxy:"proxy-networks,omitempty"`
	InstanceName        string   `proxy:"instance-name,omitempty"`
	StateDir            string   `proxy:"state-dir,omitempty"`
	UDP                 bool     `proxy:"udp,omitempty"`
	AcceptDNS           *bool    `proxy:"accept-dns,omitempty"`
	EnableExitNode      *bool    `proxy:"enable-exit-node,omitempty"`
	EnableEncryption    *bool    `proxy:"enable-encryption,omitempty"`
	EncryptionAlgorithm string   `proxy:"encryption-algorithm,omitempty"`
	PrivateMode         *bool    `proxy:"private-mode,omitempty"`
	LatencyFirst        *bool    `proxy:"latency-first,omitempty"`
	DisableP2P          *bool    `proxy:"disable-p2p,omitempty"`
	EnableKCPProxy      *bool    `proxy:"enable-kcp-proxy,omitempty"`
	DisableKCPInput     *bool    `proxy:"disable-kcp-input,omitempty"`
	EnableQUICProxy     *bool    `proxy:"enable-quic-proxy,omitempty"`
	DisableQUICInput    *bool    `proxy:"disable-quic-input,omitempty"`
	MTU                 int      `proxy:"mtu,omitempty"`
	TLDDNSZone          string   `proxy:"tld-dns-zone,omitempty"`
	SecureMode          *bool    `proxy:"secure-mode,omitempty"`
	LocalPrivateKey     string   `proxy:"local-private-key,omitempty"`
	LocalPublicKey      string   `proxy:"local-public-key,omitempty"`
}

func (o EasyTierOption) structuredConfig() easytier.Config {
	instanceName := o.InstanceName
	if instanceName == "" {
		instanceName = o.Name
	}
	return easytier.Config{
		NetworkName:         o.NetworkName,
		NetworkSecret:       o.NetworkSecret,
		Hostname:            o.Hostname,
		IPv4:                o.IPv4,
		DHCP:                o.DHCP,
		Peers:               o.Peers,
		Listeners:           o.Listeners,
		NoListener:          o.NoListener,
		MappedListeners:     o.MappedListeners,
		ExitNodes:           o.ExitNodes,
		ProxyNetworks:       o.ProxyNetworks,
		InstanceName:        instanceName,
		AcceptDNS:           o.AcceptDNS,
		EnableExitNode:      o.EnableExitNode,
		EnableEncryption:    o.EnableEncryption,
		EncryptionAlgorithm: o.EncryptionAlgorithm,
		PrivateMode:         o.PrivateMode,
		LatencyFirst:        o.LatencyFirst,
		DisableP2P:          o.DisableP2P,
		EnableKCPProxy:      o.EnableKCPProxy,
		DisableKCPInput:     o.DisableKCPInput,
		EnableQUICProxy:     o.EnableQUICProxy,
		DisableQUICInput:    o.DisableQUICInput,
		MTU:                 o.MTU,
		TLDDNSZone:          o.TLDDNSZone,
		SecureMode:          o.SecureMode,
		LocalPrivateKey:     o.LocalPrivateKey,
		LocalPublicKey:      o.LocalPublicKey,
	}
}

func NewEasyTier(option EasyTierOption) (*EasyTier, error) {
	configTOML, err := option.structuredConfig().RenderTOML()
	if err != nil {
		return nil, err
	}
	configTOML = easytier.ApplyRequiredFlags(configTOML)

	stateDir := option.StateDir
	if stateDir == "" {
		stateDir = filepath.Join(easyTierDefaultStateDir, option.Name)
	}
	stateDir = C.Path.Resolve(stateDir)
	if !C.Path.IsSafePath(stateDir) {
		return nil, C.Path.ErrNotSafePath(stateDir)
	}

	addr := option.NetworkName
	if addr == "" {
		addr = "easytier"
	}
	ctx, cancel := context.WithCancel(context.Background())
	outbound := &EasyTier{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.EasyTier,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:     option,
		configTOML: configTOML,
		stateDir:   stateDir,
		zone:       easytier.NormalizeZone(option.TLDDNSZone),
		ctx:        ctx,
		cancel:     cancel,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.unregister = dns.RegisterEasyTierDnsClient(option.Name, easyTierDNSTransport{easytier: outbound})
	return outbound, nil
}

func (e *EasyTier) start() error {
	e.startMu.Lock()
	defer e.startMu.Unlock()
	if e.closed || e.ctx.Err() != nil {
		return errEasyTierClosed
	}
	e.mu.Lock()
	instance := e.instance
	e.mu.Unlock()
	if instance != nil && instance.State() == corehost.StateRunning {
		e.startErr = nil
		return nil
	}
	_ = e.shutdown()
	if err := e.init(); err != nil {
		_ = e.shutdown()
		e.startErr = err
		return err
	}
	e.startErr = nil
	e.gen++
	e.mu.Lock()
	instance = e.instance
	gen := e.gen
	e.mu.Unlock()
	go e.supervise(instance, gen)
	return nil
}

func (e *EasyTier) ensureStarted(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- e.start()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *EasyTier) init() error {
	if err := os.MkdirAll(e.stateDir, 0o755); err != nil {
		return fmt.Errorf("easytier: create state-dir: %w", err)
	}
	instanceID := loadInstanceID(e.stateDir)
	instanceName := e.option.InstanceName
	if instanceName == "" {
		instanceName = e.option.Name
	}
	host, err := corehost.New(e.ctx, corehost.Options{
		Platform: easytier.Services(e.dialer),
	})
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.host = host
	e.mu.Unlock()

	instance, err := host.CreateInstanceTOML(e.ctx, instanceName, instanceID, e.configTOML)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.instance = instance
	e.instanceID = instance.ID()
	e.mu.Unlock()
	if err := writeInstanceID(e.stateDir, instance.ID()); err != nil {
		return err
	}
	if err := instance.Start(e.ctx); err != nil {
		return err
	}
	log.Infoln("[EasyTier](%s) instance %s running", e.Name(), instance.ID())
	return nil
}

func (e *EasyTier) currentInstance() (*corehost.Instance, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.instance == nil {
		return nil, errors.New("easytier instance is not ready")
	}
	return e.instance, nil
}

func (e *EasyTier) currentGen() uint64 {
	e.startMu.Lock()
	defer e.startMu.Unlock()
	return e.gen
}

func (e *EasyTier) supervise(instance *corehost.Instance, gen uint64) {
	if instance == nil {
		return
	}
	go e.drainEvents(instance)
	go e.drainPackets(instance)

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- instance.Wait(e.ctx)
	}()

	ticker := time.NewTicker(easyTierHealthInterval)
	defer ticker.Stop()
	grace := time.NewTimer(easyTierStartGrace)
	defer grace.Stop()
	inGrace := true
	misses := 0

	for {
		select {
		case <-e.ctx.Done():
			return
		case err := <-waitCh:
			if e.currentGen() != gen || e.ctx.Err() != nil {
				return
			}
			reason := "instance stopped"
			if err != nil {
				reason = fmt.Sprintf("instance stopped: %v", err)
			}
			e.restart(gen, reason)
			return
		case <-grace.C:
			inGrace = false
		case <-ticker.C:
			if inGrace || e.currentGen() != gen {
				continue
			}
			if e.overlayHealthy(instance) {
				misses = 0
				e.resetBackoff()
				continue
			}
			misses++
			log.Warnln("[EasyTier](%s) overlay health check failed (%d/%d)", e.Name(), misses, easyTierUnhealthyLimit)
			if misses >= easyTierUnhealthyLimit {
				e.restart(gen, "overlay disconnected")
				return
			}
		}
	}
}

func (e *EasyTier) drainEvents(instance *corehost.Instance) {
	events := instance.Events()
	if events == nil {
		return
	}
	for {
		select {
		case <-e.ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			switch event.Kind {
			case "peer_added", "peer_removed":
				log.Infoln("[EasyTier](%s) %s: %s", e.Name(), event.Kind, event.Message)
			default:
				log.Debugln("[EasyTier](%s) %s: %s", e.Name(), event.Kind, event.Message)
			}
		}
	}
}

func (e *EasyTier) drainPackets(instance *corehost.Instance) {
	for {
		if e.ctx.Err() != nil {
			return
		}
		if _, err := instance.ReceivePacket(e.ctx); err != nil {
			return
		}
	}
}

func (e *EasyTier) overlayHealthy(instance *corehost.Instance) bool {
	if instance == nil || instance.State() != corehost.StateRunning {
		return false
	}
	ctx, cancel := context.WithTimeout(e.ctx, easyTierHealthTimeout)
	defer cancel()
	if len(e.option.Peers) == 0 {
		_, err := instance.ShowNodeInfo(ctx)
		return err == nil
	}
	peers, err := instance.ListPeer(ctx)
	if err != nil {
		return false
	}
	return easyTierHasPeerConn(peers)
}

func easyTierHasPeerConn(peers []*corehost.PeerInfo) bool {
	for _, peer := range peers {
		if peer == nil {
			continue
		}
		if len(peer.GetConns()) > 0 {
			return true
		}
	}
	return false
}

func (e *EasyTier) resetBackoff() {
	e.startMu.Lock()
	e.backoff = 0
	e.startMu.Unlock()
}

func (e *EasyTier) restart(gen uint64, reason string) {
	e.startMu.Lock()
	if e.closed || e.gen != gen {
		e.startMu.Unlock()
		return
	}
	e.gen++
	backoff := e.backoff
	if backoff < easyTierMinBackoff {
		backoff = easyTierMinBackoff
	}
	next := backoff * 2
	if next > easyTierMaxBackoff {
		next = easyTierMaxBackoff
	}
	e.backoff = next
	e.startMu.Unlock()

	log.Warnln("[EasyTier](%s) %s; restarting in %s", e.Name(), reason, backoff)
	_ = e.shutdown()

	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-e.ctx.Done():
		return
	case <-timer.C:
	}
	if err := e.start(); err != nil && !errors.Is(err, errEasyTierClosed) {
		log.Errorln("[EasyTier](%s) restart failed: %v", e.Name(), err)
		go e.restart(e.currentGen(), "start failed")
	}
}

func (e *EasyTier) overlayNodes(ctx context.Context) ([]easytier.Node, error) {
	instance, err := e.currentInstance()
	if err != nil {
		return nil, err
	}
	var nodes []easytier.Node
	info, err := instance.ShowNodeInfo(ctx)
	if err == nil && info != nil {
		node := easytier.Node{Hostname: info.GetHostname()}
		if ip, parseErr := easytier.ParseNodeIPv4(info.GetIpv4Addr()); parseErr == nil {
			node.IPv4 = ip
		}
		if node.Hostname != "" || node.IPv4.IsValid() {
			nodes = append(nodes, node)
		}
	}
	routes, err := instance.ListRoute(ctx)
	if err != nil {
		if len(nodes) == 0 {
			return nil, err
		}
		return nodes, nil
	}
	for _, route := range routes {
		if route == nil {
			continue
		}
		inet := route.GetIpv4Addr()
		if inet == nil || inet.GetAddress() == nil {
			continue
		}
		nodes = append(nodes, easytier.Node{
			Hostname: route.GetHostname(),
			IPv4:     easytier.IPv4FromUint32(inet.GetAddress().GetAddr()),
		})
	}
	return nodes, nil
}

func (e *EasyTier) resolveIPv4(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !ip.Is4() {
			return netip.Addr{}, fmt.Errorf("easytier: overlay dial supports IPv4 only")
		}
		return ip, nil
	}
	nodes, err := e.overlayNodes(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	if ip, ok := easytier.LookupOverlayHost(host, e.zone, nodes); ok {
		return ip, nil
	}
	if easytier.IsMagicDNS(host, e.zone) {
		return netip.Addr{}, fmt.Errorf("easytier: overlay hostname %q was not found", host)
	}
	ips, err := resolver.LookupIPv4WithResolver(ctx, host, resolver.ProxyServerHostResolver)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("easytier: resolve %q: no IPv4 address", host)
	}
	return ips[0], nil
}

func (e *EasyTier) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = e.ensureStarted(ctx); err != nil {
		return nil, err
	}
	host := metadata.Host
	if host == "" && metadata.DstIP.IsValid() {
		host = metadata.DstIP.String()
	}
	ip, err := e.resolveIPv4(ctx, host)
	if err != nil {
		return nil, err
	}
	instance, err := e.currentInstance()
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", metadata.DstPort))
	conn, err := instance.Dial(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, e), nil
}

func (e *EasyTier) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = e.ensureStarted(ctx); err != nil {
		return nil, err
	}
	if err = e.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	instance, err := e.currentInstance()
	if err != nil {
		return nil, err
	}
	pc, err := instance.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(pc, e), nil
}

func (e *EasyTier) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata.Host != "" {
		ip, err := e.resolveIPv4(ctx, metadata.Host)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
		return nil
	}
	if metadata.DstIP.IsValid() && !metadata.DstIP.Is4() {
		return fmt.Errorf("easytier: overlay dial supports IPv4 only")
	}
	return nil
}

func (e *EasyTier) ProxyInfo() C.ProxyInfo {
	info := e.Base.ProxyInfo()
	info.DialerProxy = e.option.DialerProxy
	return info
}

func (e *EasyTier) IsL3Protocol(*C.Metadata) bool {
	return true
}

func (e *EasyTier) Close() error {
	e.cancel()
	if e.unregister != nil {
		e.unregister()
	}
	e.startMu.Lock()
	e.closed = true
	e.startErr = errEasyTierClosed
	e.startMu.Unlock()
	return e.shutdown()
}

func (e *EasyTier) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	e.mu.Lock()
	instance := e.instance
	host := e.host
	e.instance = nil
	e.host = nil
	e.mu.Unlock()
	var err error
	if instance != nil {
		err = instance.Close(ctx)
	}
	if host != nil {
		if hostErr := host.Close(ctx); err == nil {
			err = hostErr
		}
	}
	return err
}

type easyTierDNSTransport struct {
	easytier *EasyTier
}

func (t easyTierDNSTransport) Address() string {
	return "easytier://" + t.easytier.Name()
}

func (t easyTierDNSTransport) ResetConnection() {}

func (t easyTierDNSTransport) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	if err := t.easytier.ensureStarted(ctx); err != nil {
		return nil, err
	}
	q := msg.Question[0]
	nodes, err := t.easytier.overlayNodes(ctx)
	if err != nil {
		return nil, err
	}
	reply := new(D.Msg)
	reply.SetReply(msg)
	reply.Authoritative = true
	reply.RecursionAvailable = true
	switch q.Qtype {
	case D.TypeA:
		ip, ok := easytier.LookupOverlayHost(q.Name, t.easytier.zone, nodes)
		if !ok {
			reply.Rcode = D.RcodeNameError
			return reply, nil
		}
		reply.Answer = append(reply.Answer, &D.A{
			Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: easyTierDNSTTL},
			A:   ip.AsSlice(),
		})
	case D.TypePTR:
		ip, ok := easytier.ParsePTRIPv4(q.Name)
		if !ok {
			reply.Rcode = D.RcodeNameError
			return reply, nil
		}
		name, ok := easytier.LookupOverlayPTR(ip, t.easytier.zone, nodes)
		if !ok {
			reply.Rcode = D.RcodeNameError
			return reply, nil
		}
		reply.Answer = append(reply.Answer, &D.PTR{
			Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypePTR, Class: D.ClassINET, Ttl: easyTierDNSTTL},
			Ptr: name,
		})
	default:
		reply.Rcode = D.RcodeSuccess
	}
	return reply, nil
}

func loadInstanceID(stateDir string) string {
	contents, err := os.ReadFile(filepath.Join(stateDir, easyTierInstanceIDFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(contents))
}

func writeInstanceID(stateDir, id string) error {
	if id == "" {
		return nil
	}
	path := filepath.Join(stateDir, easyTierInstanceIDFile)
	return os.WriteFile(path, []byte(id+"\n"), 0o600)
}
