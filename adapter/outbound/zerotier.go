//go:build !no_zerotier

package outbound

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	M "github.com/metacubex/sing/common/metadata"
	ZT "github.com/metacubex/zerotier-go"
	ZTIP "github.com/metacubex/zerotier-go/iplink"
	ZTTransport "github.com/metacubex/zerotier-go/transport"
)

const (
	zeroTierDefaultStateDir = "zerotier"
	// zeroTierFrameQueueSize absorbs short multi-flow bursts so data frames do
	// not crowd handshake and window-update traffic out of the single ordered
	// bridge consumer.
	zeroTierFrameQueueSize = 2048
	// zeroTierFrameBatchSize amortizes runtime validation, lock acquisition,
	// and IP-stack delivery while retaining callback order.
	zeroTierFrameBatchSize       = 64
	zeroTierFrameDropLogInterval = 10 * time.Second
)

var errZeroTierClosed = errors.New("ZeroTier outbound closed")

var errZeroTierStaleConfig = errors.New("stale ZeroTier network configuration")

type ZeroTier struct {
	*Base
	option            ZeroTierOption
	networkID         uint64
	planet            *ZT.World
	orbits            []zeroTierOrbit
	remoteTraceTarget ZT.Address
	stateStore        ZT.StateStore
	dns               []dns.NameServer
	ctx               context.Context
	cancel            context.CancelFunc

	// Lock acquisition rules. Rows are locks already held; columns are locks to
	// acquire next. Any lock may be acquired when no ZeroTier lock is held.
	//
	//   +-------------+-------------+---------+
	//   | held / next | operationMu | stateMu |
	//   +-------------+-------------+---------+
	//   | operationMu |      -      |   YES   |
	//   | stateMu     |     NO      |    -    |
	//   +-------------+-------------+---------+
	//
	// Node state callbacks are serialized by zerotier-go and may run
	// synchronously while operationMu is write-locked. Data callbacks may run
	// concurrently. Both callback paths may take stateMu, but neither takes
	// operationMu; recovery that needs its write lock starts in another
	// goroutine. Control-plane operations take the write lock, while data-plane
	// use of mutable IP-link configuration takes the read lock. stateMu is only a
	// short-lived field lock and is never held while acquiring operationMu.
	operationMu       sync.RWMutex
	closed            bool
	backgroundStarted bool

	frameCh  chan zeroTierInboundFrame
	configCh chan struct{}

	// stateMu protects the current runtime pointer and network state below. A
	// runtime is immutable after publication except for its private worker
	// bookkeeping. stateMu is never held across calls into the node, IP link,
	// device, resolver, transport, or filesystem.
	stateMu              sync.RWMutex
	runtime              *zeroTierRuntime
	config               ZT.NetworkConfigData
	tunDevice            ipStack
	resolver             resolver.Resolver
	networkErr           error
	stateCh              chan struct{}
	latestConfig         ZT.NetworkConfigData
	haveLatestConfig     bool
	retryLatestConfig    bool
	networkRetrying      bool
	authURL              string
	loggedNetworkFailure string
	configGeneration     uint64
}

type ZeroTierOption struct {
	BasicOption
	Name              string                `proxy:"name"`
	Network           string                `proxy:"network"`
	StateDir          string                `proxy:"state-dir,omitempty"`
	Planet            string                `proxy:"planet,omitempty"`
	MTU               int                   `proxy:"mtu,omitempty"`
	IPStack           IPStackOption         `proxy:"ip-stack,omitempty"`
	PhysicalMTU       int                   `proxy:"physical-mtu,omitempty"`
	UDP               bool                  `proxy:"udp,omitempty"`
	RemoteDnsResolve  bool                  `proxy:"remote-dns-resolve,omitempty"`
	Dns               []string              `proxy:"dns,omitempty"`
	LowBandwidth      bool                  `proxy:"low-bandwidth,omitempty"`
	EncryptedHello    bool                  `proxy:"encrypted-hello,omitempty"`
	PrimaryPort       int                   `proxy:"primary-port,omitempty"`
	SecondaryPort     int                   `proxy:"secondary-port,omitempty"`
	TCPFallbackMode   string                `proxy:"tcp-fallback-mode,omitempty"`
	TCPFallbackRelay  string                `proxy:"tcp-fallback-relay,omitempty"`
	Orbit             []ZeroTierOrbitOption `proxy:"orbit,omitempty"`
	RemoteTraceTarget string                `proxy:"remote-trace-target,omitempty"`
	RemoteTraceLevel  uint64                `proxy:"remote-trace-level,omitempty"`
}

type ZeroTierOrbitOption struct {
	World string `proxy:"world"`
	Seed  string `proxy:"seed"`
}

type zeroTierOrbit struct {
	world uint64
	seed  ZT.Address
}

type zeroTierInboundFrame struct {
	runtime *zeroTierRuntime
	frame   ZT.Frame
}

// zeroTierRuntime owns one Node generation and all background work tied to it.
// Its lifecycle references do not change after publication; workers is used
// only by startBackgroundTasks and close under operationMu exclusion.
type zeroTierRuntime struct {
	ctx         context.Context
	cancel      context.CancelFunc
	node        *ZT.Node
	nodeAddress ZT.Address
	ipLink      *ZTIP.Link
	wire        *ZTTransport.Transport
	workers     sync.WaitGroup
}

type zeroTierStateFS struct {
	directory string
	outbound  string
}

type zeroTierPacketConn struct {
	net.PacketConn
	validateDestination func(netip.Addr) error
}

func (c *zeroTierPacketConn) WriteTo(packet []byte, destination net.Addr) (int, error) {
	address := M.SocksaddrFromNet(destination).Unwrap()
	if !address.IsIP() {
		return 0, fmt.Errorf("invalid ZeroTier UDP destination %v", destination)
	}
	if err := c.validateDestination(address.Addr); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(packet, destination)
}

func (f zeroTierStateFS) Open(name string) (fs.File, error) {
	return os.Open(filepath.Join(f.directory, filepath.FromSlash(name)))
}

func (f zeroTierStateFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	path := filepath.Join(f.directory, filepath.FromSlash(name))
	err := os.MkdirAll(filepath.Dir(path), 0700)
	if err == nil {
		err = os.WriteFile(path, data, perm)
	}
	if err != nil {
		log.Warnln("[ZeroTier](%s) unable to write state object %s: %v", f.outbound, name, err)
	}
	return err
}

func (f zeroTierStateFS) Remove(name string) error {
	return os.Remove(filepath.Join(f.directory, filepath.FromSlash(name)))
}

func NewZeroTier(option ZeroTierOption) (*ZeroTier, error) {
	networkID, err := ZT.ParseNetworkID(option.Network)
	if err != nil {
		return nil, err
	}
	if option.MTU != 0 && (option.MTU < ZT.MinNetworkMTU || option.MTU > ZT.MaxNetworkMTU) {
		return nil, fmt.Errorf("ZeroTier MTU must be between %d and %d", ZT.MinNetworkMTU, ZT.MaxNetworkMTU)
	}
	if option.PhysicalMTU != 0 && (option.PhysicalMTU < ZT.MinPhysicalMTU || option.PhysicalMTU > ZT.MaxPhysicalMTU) {
		return nil, fmt.Errorf("ZeroTier physical MTU must be between %d and %d", ZT.MinPhysicalMTU, ZT.MaxPhysicalMTU)
	}
	var planet *ZT.World
	if option.Planet != "" {
		option.Planet = C.Path.Resolve(option.Planet)
		if !C.Path.IsSafePath(option.Planet) {
			return nil, C.Path.ErrNotSafePath(option.Planet)
		}
		data, readErr := os.ReadFile(option.Planet)
		if readErr != nil {
			return nil, fmt.Errorf("read ZeroTier planet: %w", readErr)
		}
		world, parseErr := ZT.ParsePlanet(data)
		if parseErr != nil {
			return nil, fmt.Errorf("parse ZeroTier planet: %w", parseErr)
		}
		planet = &world
	}
	orbits := make([]zeroTierOrbit, 0, len(option.Orbit))
	seenWorlds := make(map[uint64]struct{}, len(option.Orbit))
	for _, orbit := range option.Orbit {
		world, seed, err := ZT.ParseOrbit(orbit.World, orbit.Seed)
		if err != nil {
			return nil, err
		}
		if _, exists := seenWorlds[world]; exists {
			return nil, fmt.Errorf("duplicate ZeroTier orbit world %016x", world)
		}
		seenWorlds[world] = struct{}{}
		orbits = append(orbits, zeroTierOrbit{world: world, seed: seed})
	}
	tcpFallbackMode, err := ZTTransport.ParseTCPFallbackMode(option.TCPFallbackMode)
	if err != nil {
		return nil, err
	}
	option.TCPFallbackMode = tcpFallbackMode.String()
	option.IPStack.normalize()
	if err = option.IPStack.validate(); err != nil {
		return nil, err
	}
	if option.TCPFallbackRelay == "" {
		option.TCPFallbackRelay = ZTTransport.DefaultTCPFallbackRelay
	}
	var remoteTraceTarget ZT.Address
	if option.RemoteTraceTarget != "" {
		remoteTraceTarget, err = ZT.ParseAddress(option.RemoteTraceTarget)
		if err != nil || remoteTraceTarget.IsReserved() {
			return nil, errors.New("ZeroTier remote trace target must be a 10-digit node ID")
		}
	}
	if option.RemoteTraceLevel > ZT.TraceLevelInsane {
		return nil, fmt.Errorf("ZeroTier remote trace level must be between %d and %d", ZT.TraceLevelNormal, ZT.TraceLevelInsane)
	}
	var nameServers []dns.NameServer
	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		nameServers, err = dns.ParseNameServer(option.Dns)
		if err != nil {
			return nil, err
		}
	}
	if option.StateDir == "" {
		instance := sha256.Sum256([]byte(option.Name))
		option.StateDir = filepath.Join(zeroTierDefaultStateDir, fmt.Sprintf("%s-%x", option.Network, instance[:6]))
	}
	option.StateDir = C.Path.Resolve(option.StateDir)
	if !C.Path.IsSafePath(option.StateDir) {
		return nil, C.Path.ErrNotSafePath(option.StateDir)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stateStore, err := ZT.NewFileStore(&zeroTierStateFS{directory: option.StateDir, outbound: option.Name})
	if err != nil {
		cancel()
		return nil, err
	}
	outbound := &ZeroTier{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         option.Network,
			Type:         C.ZeroTier,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:            option,
		networkID:         networkID,
		planet:            planet,
		orbits:            orbits,
		remoteTraceTarget: remoteTraceTarget,
		stateStore:        stateStore,
		dns:               nameServers,
		ctx:               ctx,
		cancel:            cancel,
		frameCh:           make(chan zeroTierInboundFrame, zeroTierFrameQueueSize),
		configCh:          make(chan struct{}, 1),
		stateCh:           make(chan struct{}),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	wireConfig, err := outbound.wireTransportConfig()
	if err == nil {
		err = ZTTransport.ValidateConfig(wireConfig)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	return outbound, nil
}

func (z *ZeroTier) wireTransportConfig() (ZTTransport.Config, error) {
	fallbackMode, err := ZTTransport.ParseTCPFallbackMode(z.option.TCPFallbackMode)
	if err != nil {
		return ZTTransport.Config{}, err
	}
	return ZTTransport.Config{
		Dialer:           z.dialer,
		Interfaces:       zeroTierTransportInterfaces,
		InterfaceName:    z.option.Interface,
		SharedUDP:        z.option.DialerProxy == "",
		PrimaryPort:      z.option.PrimaryPort,
		SecondaryPort:    z.option.SecondaryPort,
		TCPFallbackMode:  fallbackMode,
		TCPFallbackRelay: z.option.TCPFallbackRelay,
		Log: func(level ZTTransport.LogLevel, format string, arguments ...interface{}) {
			message := fmt.Sprintf(format, arguments...)
			if level == ZTTransport.LogInfo {
				log.Infoln("[ZeroTier](%s) %s", z.Name(), message)
			} else {
				log.Debugln("[ZeroTier](%s) %s", z.Name(), message)
			}
		},
	}, nil
}

func zeroTierTransportInterfaces() ([]ZTTransport.Interface, error) {
	interfaces, err := iface.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make([]ZTTransport.Interface, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		result = append(result, ZTTransport.Interface{
			Name:      networkInterface.Name,
			Flags:     networkInterface.Flags,
			Addresses: networkInterface.Addresses,
		})
	}
	return result, nil
}

func (z *ZeroTier) detachStackLocked() ipStack {
	device := z.tunDevice
	z.tunDevice = nil
	z.resolver = nil
	return device
}

func (z *ZeroTier) resetNetworkStateLocked(networkErr error) {
	z.config = ZT.NetworkConfigData{}
	z.latestConfig = ZT.NetworkConfigData{}
	z.haveLatestConfig = false
	z.retryLatestConfig = false
	z.networkErr = networkErr
	z.authURL = ""
	z.loggedNetworkFailure = ""
	z.configGeneration++
	z.notifyStateLocked()
}

func (z *ZeroTier) setNetworkFailureLocked(err error, authURL string, retryConfig bool) {
	z.networkErr = err
	z.authURL = authURL
	z.retryLatestConfig = retryConfig && z.haveLatestConfig
	z.notifyStateLocked()
}

func (z *ZeroTier) clearLoggedNetworkFailure(source *zeroTierRuntime) bool {
	z.stateMu.Lock()
	if z.runtime != source {
		z.stateMu.Unlock()
		return false
	}
	z.loggedNetworkFailure = ""
	z.stateMu.Unlock()
	return true
}

func (z *ZeroTier) detachRuntimeLocked() (runtime *zeroTierRuntime, device ipStack) {
	runtime = z.runtime
	device = z.detachStackLocked()
	z.runtime = nil
	return
}

// startBackgroundTasks starts the workers owned by this runtime. The caller
// holds operationMu, so the runtime cannot be detached until Add completes.
func (r *zeroTierRuntime) startBackgroundTasks() {
	r.workers.Add(2)
	go func() {
		defer r.workers.Done()
		r.node.RunBackgroundTasks(r.ctx)
	}()
	go func() {
		defer r.workers.Done()
		r.ipLink.RunBackgroundTasks(r.ctx)
	}()
}

// close stops one retired runtime before its identity or persistent state can
// be reused. Physical receive workers stop before the Node and its background
// tasks, so no transport callback can race Node.Close.
func (r *zeroTierRuntime) close(device ipStack) error {
	r.cancel()
	_ = r.wire.Close()
	r.wire.Wait()
	r.workers.Wait()
	_ = r.node.Close()
	if device != nil {
		return device.Close()
	}
	return nil
}

func (z *ZeroTier) start() error {
	z.operationMu.Lock()
	defer z.operationMu.Unlock()
	return z.startLocked()
}

func (z *ZeroTier) startLocked() error {
	if z.closed || z.ctx.Err() != nil {
		return errZeroTierClosed
	}
	z.stateMu.RLock()
	started := z.runtime != nil
	z.stateMu.RUnlock()
	if started {
		return nil
	}
	if err := os.MkdirAll(z.option.StateDir, 0700); err != nil {
		return err
	}
	wireConfig, err := z.wireTransportConfig()
	if err != nil {
		return err
	}
	wireTransport, err := ZTTransport.New(wireConfig)
	if err != nil {
		return err
	}
	runtime := &zeroTierRuntime{}
	var frameDrops struct {
		sync.Mutex
		count uint64
		last  time.Time
	}
	node, err := ZT.NewNode(ZT.NodeConfig{
		Store:  z.stateStore,
		Sender: wireTransport,
		Planet: z.planet,
		OnEvent: func(event ZT.Event) {
			z.handleNodeEvent(runtime, event)
		},
		PhysicalMTU:       z.option.PhysicalMTU,
		RemoteTraceTarget: z.remoteTraceTarget,
		RemoteTraceLevel:  z.option.RemoteTraceLevel,
		LowBandwidth:      z.option.LowBandwidth,
		EncryptedHello:    z.option.EncryptedHello,
		OnNetworkConfig: func(config ZT.NetworkConfigData) {
			z.enqueueNetworkConfig(runtime, config)
		},
		OnFrame: func(frame ZT.Frame) {
			select {
			case z.frameCh <- zeroTierInboundFrame{runtime: runtime, frame: frame}:
			default:
				now := time.Now()
				frameDrops.Lock()
				frameDrops.count++
				var dropped uint64
				if frameDrops.last.IsZero() || now.Sub(frameDrops.last) >= zeroTierFrameDropLogInterval {
					dropped = frameDrops.count
					frameDrops.count = 0
					frameDrops.last = now
				}
				frameDrops.Unlock()
				if dropped != 0 {
					log.Warnln("[ZeroTier](%s) dropped %d inbound frames because the bridge queue is full", z.Name(), dropped)
				}
			}
		},
		DirectPaths: wireTransport.DirectPaths,
	})
	if err != nil {
		_ = wireTransport.Close()
		return err
	}
	ipLink, err := ZTIP.New(z.networkID, node)
	if err != nil {
		_ = wireTransport.Close()
		_ = node.Close()
		return err
	}
	runtimeCtx, runtimeCancel := context.WithCancel(z.ctx)
	runtime.ctx = runtimeCtx
	runtime.cancel = runtimeCancel
	runtime.node = node
	runtime.nodeAddress = node.Address()
	runtime.ipLink = ipLink
	runtime.wire = wireTransport
	z.stateMu.Lock()
	z.runtime = runtime
	z.resetNetworkStateLocked(nil)
	z.stateMu.Unlock()
	cleanup := func(startErr error) error {
		z.stateMu.Lock()
		if z.runtime == runtime {
			z.runtime = nil
		}
		z.stateMu.Unlock()
		_ = runtime.close(nil)
		return startErr
	}
	if err = wireTransport.Start(runtimeCtx, node); err != nil {
		return cleanup(err)
	}
	for _, orbit := range z.orbits {
		if err = node.Orbit(orbit.world, orbit.seed); err != nil {
			return cleanup(fmt.Errorf("orbit ZeroTier world %016x: %w", orbit.world, err))
		}
	}
	if err = node.Join(z.networkID); err != nil {
		return cleanup(err)
	}
	if !z.backgroundStarted {
		z.backgroundStarted = true
		go z.runNetworkConfig()
		go z.runInboundFrames()
	}
	runtime.startBackgroundTasks()
	return nil
}

func (z *ZeroTier) enqueueNetworkConfig(source *zeroTierRuntime, config ZT.NetworkConfigData) {
	if z.ctx.Err() != nil || source == nil || source.node == nil {
		return
	}
	network, ok := source.node.Network(z.networkID)
	if !ok || network.Status != ZT.NetworkStatusOK || !network.Config.Equal(config) {
		return
	}
	z.stateMu.Lock()
	if z.ctx.Err() != nil || z.runtime != source {
		z.stateMu.Unlock()
		return
	}
	z.latestConfig = config
	z.haveLatestConfig = true
	z.stateMu.Unlock()
	select {
	case z.configCh <- struct{}{}:
	default:
	}
}

func (z *ZeroTier) ensureStarted(ctx context.Context) error {
	if err := z.start(); err != nil {
		return err
	}
	z.retryNetwork()
	for {
		z.stateMu.RLock()
		networkErr := z.networkErr
		device := z.tunDevice
		stateCh := z.stateCh
		z.stateMu.RUnlock()
		if device != nil && networkErr == nil {
			return nil
		}
		if networkErr != nil {
			return networkErr
		}
		select {
		case <-stateCh:
		case <-ctx.Done():
			return ctx.Err()
		case <-z.ctx.Done():
			return errZeroTierClosed
		}
	}
}

func (z *ZeroTier) notifyStateLocked() {
	close(z.stateCh)
	z.stateCh = make(chan struct{})
}

func (z *ZeroTier) runNetworkConfig() {
	for {
		select {
		case <-z.configCh:
			z.stateMu.RLock()
			runtime := z.runtime
			config := z.latestConfig
			haveConfig := z.haveLatestConfig
			generation := z.configGeneration
			z.stateMu.RUnlock()
			if !haveConfig {
				continue
			}
			if err := z.applyNetworkConfig(config, generation); err != nil && !errors.Is(err, errZeroTierStaleConfig) {
				if z.recordConfigFailure(runtime, config, generation, err) {
					log.Errorln("[ZeroTier](%s) apply network configuration: %v", z.Name(), err)
				}
			}
		case <-z.ctx.Done():
			return
		}
	}
}

func (z *ZeroTier) handleNodeEvent(source *zeroTierRuntime, event ZT.Event) {
	if !z.acceptNodeEvent(source, event) {
		return
	}
	switch event.Type {
	case ZT.EventNodeDown:
		log.Debugln("[ZeroTier](%s) node %s shut down", z.Name(), event.NodeAddress)
	case ZT.EventNodeUp:
		if ZT.IsAdHocNetworkID(z.networkID) {
			log.Infoln("[ZeroTier](%s) node %s initialized", z.Name(), event.NodeAddress)
		} else {
			log.Infoln("[ZeroTier](%s) node %s initialized; authorize this ID on network %016x", z.Name(), event.NodeAddress, z.networkID)
		}
	case ZT.EventNodeOnline:
		log.Infoln("[ZeroTier](%s) node %s is online via %s", z.Name(), event.NodeAddress, event.Endpoint)
	case ZT.EventNodeOffline:
		log.Warnln("[ZeroTier](%s) node %s is offline", z.Name(), event.NodeAddress)
	case ZT.EventNodeIdentityCollision:
		go z.recoverIdentityCollision(source, event.NodeAddress)
	case ZT.EventPeerIdentityLearned:
		if event.PeerRole != ZT.PeerRoleLeaf {
			log.Debugln("[ZeroTier](%s) loaded %s root identity %s", z.Name(), event.PeerRole, event.PeerAddress)
		} else {
			log.Debugln("[ZeroTier](%s) loaded peer identity %s", z.Name(), event.PeerAddress)
		}
	case ZT.EventPeerPathLearned:
		if event.PeerRole != ZT.PeerRoleLeaf {
			log.Debugln("[ZeroTier](%s) %s root %s authenticated path %s", z.Name(), event.PeerRole, event.PeerAddress, event.Endpoint)
		} else {
			log.Debugln("[ZeroTier](%s) peer %s authenticated path %s", z.Name(), event.PeerAddress, event.Endpoint)
		}
	case ZT.EventPeerRouteChanged:
		switch event.Route {
		case ZT.PeerRouteDirect:
			if event.Endpoint.IsValid() {
				log.Debugln("[ZeroTier](%s) peer %s selected direct route via %s", z.Name(), event.PeerAddress, event.Endpoint)
			} else {
				log.Debugln("[ZeroTier](%s) peer %s selected %d direct paths", z.Name(), event.PeerAddress, event.PathCount)
			}
		case ZT.PeerRouteRelayed:
			log.Debugln("[ZeroTier](%s) peer %s selected upstream relay route", z.Name(), event.PeerAddress)
		default:
			log.Debugln("[ZeroTier](%s) peer %s selected unknown route %d", z.Name(), event.PeerAddress, event.Route)
		}
	case ZT.EventLocalSurfaceChanged:
		log.Debugln("[ZeroTier](%s) external surface changed %s -> %s after report from %s root %s; revalidating %d paths", z.Name(), event.PreviousEndpoint, event.Endpoint, event.PeerRole, event.ReporterAddress, event.PathCount)
	case ZT.EventNetworkConfigPending:
		log.Debugln("[ZeroTier](%s) requesting configuration for network %016x", z.Name(), event.NetworkID)
	case ZT.EventNetworkConfigReady:
		if !z.clearLoggedNetworkFailure(source) {
			return
		}
		if ZT.IsAdHocNetworkID(event.NetworkID) {
			log.Infoln("[ZeroTier](%s) network %016x ad-hoc configuration created", z.Name(), event.NetworkID)
		} else {
			log.Infoln("[ZeroTier](%s) network %016x controller configuration accepted", z.Name(), event.NetworkID)
		}
	case ZT.EventNetworkConfigChanged:
		if !z.clearLoggedNetworkFailure(source) {
			return
		}
		if ZT.IsAdHocNetworkID(event.NetworkID) {
			log.Debugln("[ZeroTier](%s) network %016x ad-hoc configuration refresh accepted", z.Name(), event.NetworkID)
		} else {
			log.Debugln("[ZeroTier](%s) network %016x controller configuration update accepted", z.Name(), event.NetworkID)
		}
	case ZT.EventNetworkAccessDenied:
		networkErr := errors.New("ZeroTier network access denied")
		if shouldLog := z.invalidateNetwork(source, networkErr, "", false); shouldLog {
			log.Warnln("[ZeroTier](%s) network %016x access denied", z.Name(), event.NetworkID)
		}
	case ZT.EventNetworkNotFound:
		var networkErr error
		if ZT.IsAdHocNetworkID(event.NetworkID) {
			networkErr = errors.New("unsupported ZeroTier ad-hoc network ID")
		} else {
			networkErr = errors.New("ZeroTier network not found or controller unsupported")
		}
		if shouldLog := z.invalidateNetwork(source, networkErr, "", false); shouldLog {
			log.Warnln("[ZeroTier](%s) network %016x: %v", z.Name(), event.NetworkID, networkErr)
		}
	case ZT.EventNetworkAuthenticationRequired:
		authURL, err := event.Authentication.LoginURL()
		if err != nil {
			networkErr := fmt.Errorf("ZeroTier network authentication required: %w", err)
			if shouldLog := z.invalidateNetwork(source, networkErr, "", false); shouldLog {
				log.Warnln("[ZeroTier](%s) network %016x: %v", z.Name(), event.NetworkID, networkErr)
			}
			return
		}
		if shouldLog := z.invalidateNetwork(source, nil, authURL, false); shouldLog {
			log.Infoln("[ZeroTier](%s) network %016x authentication required; complete login at %s", z.Name(), event.NetworkID, authURL)
		}
	case ZT.EventNetworkLeft:
		if shouldLog := z.invalidateNetwork(source, errors.New("ZeroTier network was left"), "", false); shouldLog {
			log.Warnln("[ZeroTier](%s) network %016x was left", z.Name(), event.NetworkID)
		}
	default:
		log.Debugln("[ZeroTier](%s) ignored unknown node event %d", z.Name(), event.Type)
	}
}

// acceptNodeEvent rejects callbacks from retired runtimes and network events
// superseded before delivery. NodeDown remains useful after detach. Constructor
// callbacks use an allocated but not yet published runtime whose Node is nil.
func (z *ZeroTier) acceptNodeEvent(source *zeroTierRuntime, event ZT.Event) bool {
	if event.Type == ZT.EventNodeDown {
		return true
	}
	if z.ctx.Err() != nil {
		return false
	}
	if source == nil {
		return false
	}
	if source.node == nil {
		return true
	}
	z.stateMu.RLock()
	current := z.runtime == source
	z.stateMu.RUnlock()
	return current && event.MatchesNodeState(source.node)
}

func (z *ZeroTier) recoverIdentityCollision(source *zeroTierRuntime, address ZT.Address) {
	z.operationMu.Lock()
	defer z.operationMu.Unlock()
	if z.closed || z.ctx.Err() != nil {
		return
	}
	z.stateMu.Lock()
	if z.runtime != source || source == nil || source.nodeAddress != address {
		z.stateMu.Unlock()
		return
	}
	runtime, device := z.detachRuntimeLocked()
	z.resetNetworkStateLocked(nil)
	z.stateMu.Unlock()

	_ = runtime.close(device)
	if err := ZT.RotateIdentityState(z.stateStore); err != nil {
		log.Warnln("[ZeroTier](%s) unable to rotate collided identity: %v", z.Name(), err)
	}
	log.Warnln("[ZeroTier](%s) node %s has an identity collision; generating a new identity", z.Name(), address)
	startErr := z.startLocked()
	if startErr != nil && !errors.Is(startErr, errZeroTierClosed) {
		log.Errorln("[ZeroTier](%s) restart after identity collision: %v", z.Name(), startErr)
		z.invalidateNetwork(nil, startErr, "", false)
	}
}

func (z *ZeroTier) retryNetwork() {
	z.stateMu.Lock()
	if z.ctx.Err() != nil {
		z.stateMu.Unlock()
		return
	}
	if z.tunDevice != nil && z.networkErr == nil {
		z.stateMu.Unlock()
		return
	}
	if z.networkRetrying {
		z.stateMu.Unlock()
		return
	}
	z.networkRetrying = true
	z.networkErr = nil
	retryConfig := z.retryLatestConfig && z.haveLatestConfig
	haveConfig := z.haveLatestConfig
	config := z.latestConfig
	runtime := z.runtime
	generation := z.configGeneration
	z.stateMu.Unlock()
	defer func() {
		z.stateMu.Lock()
		z.networkRetrying = false
		z.stateMu.Unlock()
	}()
	if retryConfig {
		if err := z.applyNetworkConfig(config, generation); err == nil {
			return
		} else if !errors.Is(err, errZeroTierStaleConfig) {
			z.recordConfigFailure(runtime, config, generation, err)
		}
	}
	if runtime == nil {
		return
	}
	operation := "refresh network configuration"
	var err error
	if _, joined := runtime.node.Network(z.networkID); joined {
		err = runtime.node.RefreshNetwork(z.networkID)
	} else {
		operation = "rejoin network"
		err = runtime.node.Join(z.networkID)
	}
	if err != nil {
		recorded := false
		z.stateMu.Lock()
		if z.ctx.Err() == nil && z.configSnapshotCurrentLocked(runtime, config, haveConfig, generation) {
			z.setNetworkFailureLocked(fmt.Errorf("%s: %w", operation, err), z.authURL, z.retryLatestConfig)
			recorded = true
		}
		z.stateMu.Unlock()
		if recorded {
			if retryConfig {
				log.Debugln("[ZeroTier](%s) %s after local apply failure: %v", z.Name(), operation, err)
			} else {
				log.Debugln("[ZeroTier](%s) %s: %v", z.Name(), operation, err)
			}
		}
	}
}

func (z *ZeroTier) recordConfigFailure(runtime *zeroTierRuntime, config ZT.NetworkConfigData, generation uint64, err error) bool {
	z.stateMu.Lock()
	defer z.stateMu.Unlock()
	if z.ctx.Err() != nil || !z.configSnapshotCurrentLocked(runtime, config, true, generation) {
		return false
	}
	z.setNetworkFailureLocked(err, z.authURL, true)
	return true
}

// invalidateNetwork detaches the virtual stack and publishes a network
// failure. A non-nil source limits the mutation to that runtime generation. It
// reports whether this failure differs from the last logged failure.
func (z *ZeroTier) invalidateNetwork(source *zeroTierRuntime, err error, authURL string, retryConfig bool) (shouldLog bool) {
	z.stateMu.Lock()
	if z.ctx.Err() != nil || source != nil && z.runtime != source {
		z.stateMu.Unlock()
		return false
	}
	device := z.detachStackLocked()
	if !retryConfig {
		z.latestConfig = ZT.NetworkConfigData{}
		z.haveLatestConfig = false
	}
	failure := ""
	if authURL != "" {
		failure = "authentication-required:" + authURL
	} else if err != nil {
		failure = err.Error()
	}
	shouldLog = z.loggedNetworkFailure != failure
	z.loggedNetworkFailure = failure
	z.configGeneration++
	z.setNetworkFailureLocked(err, authURL, retryConfig)
	z.stateMu.Unlock()
	if device != nil {
		go func() { _ = device.Close() }()
	}
	return shouldLog
}

func (z *ZeroTier) invalidateDevice(device ipStack, err error) bool {
	z.stateMu.Lock()
	if z.ctx.Err() != nil || z.tunDevice != device {
		z.stateMu.Unlock()
		return false
	}
	z.detachStackLocked()
	z.setNetworkFailureLocked(err, z.authURL, true)
	z.stateMu.Unlock()
	go func() { _ = device.Close() }()
	return true
}

func (z *ZeroTier) applyNetworkConfig(config ZT.NetworkConfigData, generation uint64) error {
	z.operationMu.Lock()
	defer z.operationMu.Unlock()
	if z.ctx.Err() != nil {
		return errZeroTierClosed
	}
	z.stateMu.RLock()
	runtime := z.runtime
	if !z.networkConfigCurrentLocked(runtime, config, generation) {
		z.stateMu.RUnlock()
		return errZeroTierStaleConfig
	}
	oldDevice := z.tunDevice
	oldConfig := z.config
	z.stateMu.RUnlock()
	if runtime == nil {
		return errors.New("ZeroTier core is not started")
	}
	ipLink := runtime.ipLink
	if len(config.Assigned) == 0 {
		return errors.New("ZeroTier controller assigned no managed addresses")
	}
	remoteResolver, err := z.resolverForNetworkConfig(config)
	if err != nil {
		return err
	}
	mtu := z.effectiveMTU(config)
	replaceDevice := oldDevice == nil || !oldConfig.ManagedAddressesEqual(config) || z.effectiveMTU(oldConfig) != mtu
	device := oldDevice
	if replaceDevice {
		device, err = newIPStack(z.option.IPStack, config.Assigned, mtu)
		if err != nil {
			return fmt.Errorf("create ZeroTier stack device: %w", err)
		}
		if err = device.Start(); err != nil {
			_ = device.Close()
			return err
		}
		if z.ctx.Err() != nil {
			_ = device.Close()
			return errZeroTierClosed
		}
	}
	z.stateMu.RLock()
	current := z.tunDevice == oldDevice && z.networkConfigCurrentLocked(runtime, config, generation)
	z.stateMu.RUnlock()
	if !current {
		if replaceDevice {
			_ = device.Close()
		}
		return errZeroTierStaleConfig
	}
	if err = ipLink.ApplyNetworkConfig(config); err != nil {
		if replaceDevice {
			_ = device.Close()
		}
		return err
	}
	z.stateMu.Lock()
	if z.tunDevice != oldDevice || !z.networkConfigCurrentLocked(runtime, config, generation) {
		z.stateMu.Unlock()
		var rollbackErr error
		if oldConfig.NetworkID == z.networkID && len(oldConfig.Assigned) != 0 {
			rollbackErr = ipLink.ApplyNetworkConfig(oldConfig)
		}
		if replaceDevice {
			_ = device.Close()
		}
		if rollbackErr != nil {
			log.Warnln("[ZeroTier](%s) restore IP link after stale configuration: %v", z.Name(), rollbackErr)
		}
		return errZeroTierStaleConfig
	}
	replacedDevice := z.tunDevice
	z.config = config
	z.tunDevice = device
	z.resolver = remoteResolver
	z.networkErr = nil
	z.authURL = ""
	z.retryLatestConfig = false
	z.configGeneration++
	appliedGeneration := z.configGeneration
	z.notifyStateLocked()
	z.stateMu.Unlock()
	var resetErr error
	if replaceDevice {
		resetErr = ipLink.ResetMulticast()
		z.stateMu.RLock()
		current = z.runtime == runtime && z.tunDevice == device && z.configGeneration == appliedGeneration
		z.stateMu.RUnlock()
		if !current {
			if replacedDevice != nil {
				_ = replacedDevice.Close()
			}
			if resetErr != nil {
				log.Debugln("[ZeroTier](%s) reset multicast subscriptions: %v", z.Name(), resetErr)
			}
			return errZeroTierStaleConfig
		}
	}
	if resetErr != nil {
		log.Debugln("[ZeroTier](%s) reset multicast subscriptions: %v", z.Name(), resetErr)
	}
	if !replaceDevice {
		return nil
	}
	go z.runStackPackets(runtime, device)
	action := "joined"
	if replacedDevice != nil {
		_ = replacedDevice.Close()
		action = "updated"
	}
	log.Infoln("[ZeroTier](%s) %s network %016x (%s), addresses=%v routes=%v mtu=%d", z.Name(), action, config.NetworkID, config.Name, config.Assigned, config.Routes, mtu)
	return nil
}

func (z *ZeroTier) networkConfigCurrentLocked(runtime *zeroTierRuntime, config ZT.NetworkConfigData, generation uint64) bool {
	return z.configSnapshotCurrentLocked(runtime, config, true, generation)
}

func (z *ZeroTier) configSnapshotCurrentLocked(runtime *zeroTierRuntime, config ZT.NetworkConfigData, haveConfig bool, generation uint64) bool {
	return z.configGeneration == generation && z.runtime == runtime && z.haveLatestConfig == haveConfig && (!haveConfig || z.latestConfig.Equal(config))
}

func (z *ZeroTier) effectiveMTU(config ZT.NetworkConfigData) uint32 {
	mtu := config.MTU
	if z.option.MTU != 0 && uint32(z.option.MTU) < mtu {
		mtu = uint32(z.option.MTU)
	}
	return mtu
}

func (z *ZeroTier) resolverForNetworkConfig(config ZT.NetworkConfigData) (resolver.Resolver, error) {
	if !z.option.RemoteDnsResolve {
		return nil, nil
	}
	nameServers := z.dns
	if len(nameServers) == 0 && len(config.DNSServers) != 0 {
		servers := make([]string, 0, len(config.DNSServers))
		for _, server := range config.DNSServers {
			if server.Port() == 0 {
				servers = append(servers, server.Addr().String())
			} else {
				servers = append(servers, server.String())
			}
		}
		var err error
		nameServers, err = dns.ParseNameServer(servers)
		if err != nil {
			return nil, fmt.Errorf("parse ZeroTier controller DNS servers: %w", err)
		}
	}
	if len(nameServers) == 0 {
		return nil, nil
	}
	nameServers = append([]dns.NameServer(nil), nameServers...)
	for i := range nameServers {
		nameServers[i].ProxyAdapter = z
	}
	return resolver.Resolver(dns.NewResolver(dns.Config{Main: nameServers, IPv6: config.HasManagedIPv6()})), nil
}

func (z *ZeroTier) runStackPackets(runtime *zeroTierRuntime, device ipStack) {
	mtu, err := device.MTU()
	if err != nil || mtu < 1 {
		mtu = 64 * 1024
	}
	batchSize := device.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	storage := make([]byte, mtu*batchSize)
	buffers := make([][]byte, batchSize)
	for index := range buffers {
		start := index * mtu
		buffers[index] = storage[start : start+mtu : start+mtu]
	}
	sizes := make([]int, batchSize)
	writeErrors := make([]error, 0, batchSize)
	for z.ctx.Err() == nil {
		count, readErr := device.Read(buffers, sizes, 0)
		if readErr != nil {
			if z.ctx.Err() == nil {
				invalidated := z.invalidateDevice(device, fmt.Errorf("ZeroTier stack read failed: %w", readErr))
				if invalidated && !errors.Is(readErr, net.ErrClosed) && !errors.Is(readErr, os.ErrClosed) {
					log.Errorln("[ZeroTier](%s) stack read: %v", z.Name(), readErr)
				}
			}
			return
		}
		z.operationMu.RLock()
		z.stateMu.RLock()
		current := z.runtime == runtime && z.tunDevice == device
		z.stateMu.RUnlock()
		if !current {
			z.operationMu.RUnlock()
			return
		}
		writeErrors = writeErrors[:0]
		for index := 0; index < count; index++ {
			if writeErr := runtime.ipLink.WritePacket(buffers[index][:sizes[index]]); writeErr != nil {
				writeErrors = append(writeErrors, writeErr)
			}
		}
		z.operationMu.RUnlock()
		for _, writeErr := range writeErrors {
			log.Debugln("[ZeroTier](%s) send IP packet: %v", z.Name(), writeErr)
		}
	}
}

func (z *ZeroTier) runInboundFrames() {
	frames := make([]zeroTierInboundFrame, zeroTierFrameBatchSize)
	packets := make([][]byte, 0, zeroTierFrameBatchSize)
	frameErrors := make([]error, 0, zeroTierFrameBatchSize)
	for {
		var first zeroTierInboundFrame
		select {
		case first = <-z.frameCh:
		case <-z.ctx.Done():
			return
		}
		frames[0] = first
		count := 1
	drain:
		for count < len(frames) {
			select {
			case frames[count] = <-z.frameCh:
				count++
			default:
				break drain
			}
		}
		device, output, processingErrors := z.processInboundFrames(frames[:count], packets[:0], frameErrors[:0])
		for _, err := range processingErrors {
			log.Debugln("[ZeroTier](%s) process inbound frame: %v", z.Name(), err)
		}
		if device != nil && len(output) != 0 {
			if _, writeErr := device.Write(output, 0); writeErr != nil && z.ctx.Err() == nil {
				invalidated := z.invalidateDevice(device, fmt.Errorf("ZeroTier stack write failed: %w", writeErr))
				if invalidated && !errors.Is(writeErr, net.ErrClosed) && !errors.Is(writeErr, os.ErrClosed) {
					log.Debugln("[ZeroTier](%s) stack write: %v", z.Name(), writeErr)
				}
			}
		}
		for index := 0; index < count; index++ {
			frames[index] = zeroTierInboundFrame{}
		}
		packets, frameErrors = output, processingErrors
	}
}

// processInboundFrames converts one callback-order batch while preventing a
// concurrent configuration update from mutating its IP link. Stack delivery
// follows after the read lock is released.
func (z *ZeroTier) processInboundFrames(frames []zeroTierInboundFrame, packets [][]byte, frameErrors []error) (ipStack, [][]byte, []error) {
	z.operationMu.RLock()
	z.stateMu.RLock()
	runtime := z.runtime
	device := z.tunDevice
	z.stateMu.RUnlock()
	if runtime == nil {
		z.operationMu.RUnlock()
		return nil, packets, frameErrors
	}
	for _, inbound := range frames {
		if inbound.runtime != runtime {
			continue
		}
		packet, err := runtime.ipLink.HandleFrame(inbound.frame)
		if err != nil {
			frameErrors = append(frameErrors, err)
		}
		if len(packet) != 0 {
			packets = append(packets, packet)
		}
	}
	z.operationMu.RUnlock()
	return device, packets, frameErrors
}

func (z *ZeroTier) networkStackFor(destination netip.Addr) (*ZTIP.Link, ipStack, error) {
	z.operationMu.RLock()
	defer z.operationMu.RUnlock()
	z.stateMu.RLock()
	runtime := z.runtime
	device := z.tunDevice
	networkErr := z.networkErr
	z.stateMu.RUnlock()
	if runtime == nil {
		return nil, nil, errors.New("ZeroTier core is not ready")
	}
	ipLink := runtime.ipLink
	if networkErr != nil {
		return nil, nil, networkErr
	}
	if device == nil {
		return nil, nil, errors.New("ZeroTier stack is not ready")
	}
	if err := ipLink.ValidateDestination(destination); err != nil {
		return nil, nil, err
	}
	z.stateMu.RLock()
	current := z.runtime == runtime && z.tunDevice == device && z.networkErr == nil
	z.stateMu.RUnlock()
	if !current {
		return nil, nil, errors.New("ZeroTier stack changed while validating destination")
	}
	return ipLink, device, nil
}

type zeroTierNetDialer struct {
	zeroTier *ZeroTier
}

func (d zeroTierNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	destination, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	_, device, err := d.zeroTier.networkStackFor(destination.Addr())
	if err != nil {
		return nil, err
	}
	return device.DialTCP(ctx, network, netip.AddrPort{}, destination)
}

func (z *ZeroTier) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = z.ensureStarted(ctx); err != nil {
		return nil, err
	}
	z.stateMu.RLock()
	remoteResolver := z.resolver
	z.stateMu.RUnlock()
	var conn net.Conn
	if !metadata.Resolved() || remoteResolver != nil {
		r := resolver.DefaultResolver
		if remoteResolver != nil {
			r = remoteResolver
		}
		options := z.DialOptions()
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(zeroTierNetDialer{zeroTier: z}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = (zeroTierNetDialer{zeroTier: z}).DialContext(ctx, "tcp", metadata.AddrPort().String())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, z), nil
}

func (z *ZeroTier) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = z.ensureStarted(ctx); err != nil {
		return nil, err
	}
	if err = z.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	ipLink, device, err := z.networkStackFor(metadata.DstIP)
	if err != nil {
		return nil, err
	}
	// The ipStack contract guarantees that a generic UDP wildcard supports both address families.
	packetConn, err := device.ListenUDP(ctx, "udp", netip.AddrPort{})
	if err != nil {
		return nil, err
	}
	if packetConn == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(&zeroTierPacketConn{PacketConn: packetConn, validateDestination: func(destination netip.Addr) error {
		currentLink, currentDevice, validateErr := z.networkStackFor(destination)
		if validateErr != nil {
			return validateErr
		}
		if currentLink != ipLink || currentDevice != device {
			return errors.New("ZeroTier stack changed while packet connection was active")
		}
		return nil
	}}, z), nil
}

func (z *ZeroTier) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	z.stateMu.RLock()
	remoteResolver := z.resolver
	z.stateMu.RUnlock()
	if (!metadata.Resolved() || remoteResolver != nil) && metadata.Host != "" {
		r := resolver.DefaultResolver
		if remoteResolver != nil {
			r = remoteResolver
		}
		ip, err := resolveIPWithResolver(ctx, metadata.Host, z.prefer, r)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (z *ZeroTier) ProxyInfo() C.ProxyInfo {
	info := z.Base.ProxyInfo()
	info.DialerProxy = z.option.DialerProxy
	return info
}

func (z *ZeroTier) IsL3Protocol(*C.Metadata) bool {
	return true
}

func (z *ZeroTier) Close() error {
	// Cancel and close the physical transport before waiting for operationMu so
	// an in-flight startup dial or wire write cannot prevent its own shutdown.
	z.cancel()
	z.stateMu.RLock()
	runtime := z.runtime
	z.stateMu.RUnlock()
	if runtime != nil {
		_ = runtime.wire.Close()
	}
	z.operationMu.Lock()
	if z.closed {
		z.operationMu.Unlock()
		return nil
	}
	z.closed = true
	z.stateMu.Lock()
	runtime, device := z.detachRuntimeLocked()
	z.resetNetworkStateLocked(errZeroTierClosed)
	z.stateMu.Unlock()
	z.operationMu.Unlock()
	if runtime != nil {
		return runtime.close(device)
	}
	if device != nil {
		return device.Close()
	}
	return nil
}
