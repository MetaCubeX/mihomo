package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

type Tailscale struct {
	*Base
	server    *tsnet.Server
	initOnce  sync.Once
	initErr   error
	option    TailscaleOption
	closeOnce sync.Once
}

type TailscaleOption struct {
	BasicOption
	Name         string `proxy:"name"`
	Hostname     string `proxy:"hostname"`
	AuthKey      string `proxy:"authkey,omitempty"`
	ControlURL   string `proxy:"control-url,omitempty"`
	Ephemeral    bool   `proxy:"ephemeral,omitempty"`
	StateDir     string `proxy:"state-dir,omitempty"`
	AcceptRoutes bool   `proxy:"accept-routes,omitempty"`
	ExitNode     string `proxy:"exit-node,omitempty"`
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err := t.initialize(); err != nil {
		return nil, fmt.Errorf("tailscale init failed: %w", err)
	}

	address := metadata.RemoteAddress()
	c, err := t.server.Dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	return NewConn(c, t), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err := t.initialize(); err != nil {
		return nil, fmt.Errorf("tailscale init failed: %w", err)
	}

	if err := t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	pc, err := t.server.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}

	return newPacketConn(&tailscalePacketConn{
		PacketConn: pc,
		rAddr:      metadata.UDPAddr(),
	}, t), nil
}

func (t *Tailscale) initialize() error {
	t.initOnce.Do(func() {
		t.initErr = t.init()
	})
	return t.initErr
}

func (t *Tailscale) init() error {
	stateDir := t.option.StateDir
	if stateDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir failed: %w", err)
		}
		stateDir = filepath.Join(homeDir, ".config", "mihomo", "tailscale", t.option.Name)
	}

	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir failed: %w", err)
	}

	srv := &tsnet.Server{
		Hostname:  t.option.Hostname,
		AuthKey:   t.option.AuthKey,
		Dir:       stateDir,
		Ephemeral: t.option.Ephemeral,
		UserLogf:  log.Infoln,
	}

	if t.option.ControlURL != "" {
		srv.ControlURL = t.option.ControlURL
	}

	t.server = srv

	log.Infoln("Tailscale [%s] starting, hostname: %s", t.option.Name, t.option.Hostname)

	// Temporarily restore net.DefaultResolver.Dial to allow tsnet to use system DNS
	// tsnet needs to resolve control plane addresses during initialization
	oldDial := net.DefaultResolver.Dial
	net.DefaultResolver.Dial = nil
	defer func() {
		net.DefaultResolver.Dial = oldDial
	}()

	// Use a background context with timeout to avoid blocking
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := srv.Up(ctx); err != nil {
		return fmt.Errorf("tailscale up failed: %w", err)
	}

	// Apply AcceptRoutes and ExitNode settings if specified
	if t.option.AcceptRoutes || t.option.ExitNode != "" {
		if err := t.applyPrefs(ctx); err != nil {
			return fmt.Errorf("apply prefs failed: %w", err)
		}
	}

	log.Infoln("Tailscale [%s] started successfully", t.option.Name)
	return nil
}

func (t *Tailscale) Close() error {
	var err error
	t.closeOnce.Do(func() {
		if t.server != nil {
			log.Infoln("Closing Tailscale [%s]", t.option.Name)
			err = t.server.Close()
		}
	})
	return err
}

func (t *Tailscale) applyPrefs(ctx context.Context) error {
	lc, err := t.server.LocalClient()
	if err != nil {
		return fmt.Errorf("get local client failed: %w", err)
	}

	maskedPrefs := &ipn.MaskedPrefs{}

	// Set AcceptRoutes (RouteAll)
	if t.option.AcceptRoutes {
		maskedPrefs.RouteAll = true
		maskedPrefs.RouteAllSet = true
		log.Infoln("Tailscale [%s] enabling accept-routes", t.option.Name)
	}

	// Set ExitNode
	if t.option.ExitNode != "" {
		// Try to parse as IP address first
		if ip, err := netip.ParseAddr(t.option.ExitNode); err == nil {
			maskedPrefs.ExitNodeIP = ip
			maskedPrefs.ExitNodeIPSet = true
			log.Infoln("Tailscale [%s] setting exit node IP: %s", t.option.Name, t.option.ExitNode)
		} else {
			// Otherwise treat as StableNodeID
			maskedPrefs.ExitNodeID = tailcfg.StableNodeID(t.option.ExitNode)
			maskedPrefs.ExitNodeIDSet = true
			log.Infoln("Tailscale [%s] setting exit node ID: %s", t.option.Name, t.option.ExitNode)
		}
	}

	if _, err := lc.EditPrefs(ctx, maskedPrefs); err != nil {
		return fmt.Errorf("edit prefs failed: %w", err)
	}

	return nil
}

type tailscalePacketConn struct {
	net.PacketConn
	rAddr net.Addr
}

func (pc *tailscalePacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return pc.PacketConn.WriteTo(b, pc.rAddr)
}

func (pc *tailscalePacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, _, err = pc.PacketConn.ReadFrom(b)
	addr = pc.rAddr
	return
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	if option.Hostname == "" {
		return nil, fmt.Errorf("tailscale hostname is required")
	}

	return &Tailscale{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         option.Hostname,
			Type:         C.Tailscale,
			ProviderName: option.ProviderName,
			UDP:          true,
			XUDP:         false,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: option,
	}, nil
}
