package listener

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/redir"
	embedSS "github.com/metacubex/mihomo/listener/shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/listener/tproxy"
	"github.com/metacubex/mihomo/listener/tuic"
	LT "github.com/metacubex/mihomo/listener/tunnel"
	"github.com/metacubex/mihomo/log"

	"github.com/samber/lo"
)

var (
	allowLan    = false
	bindAddress = "*"

	socksListener       *socks.Listener
	socksUDPListener    *socks.UDPListener
	httpListener        *http.Listener
	redirListener       *redir.Listener
	redirUDPListener    *tproxy.UDPListener
	tproxyListener      *tproxy.Listener
	tproxyUDPListener   *tproxy.UDPListener
	mixedListener       *mixed.Listener
	mixedUDPLister      *socks.UDPListener
	tunnelTCPListeners  = map[string]*LT.Listener{}
	tunnelUDPListeners  = map[string]*LT.PacketConn{}
	inboundListeners    = map[string]C.InboundListener{}
	tunLister           *sing_tun.Listener
	shadowSocksListener C.MultiAddrListener
	vmessListener       *sing_vmess.Listener
	tuicListener        *tuic.Listener

	// lock for recreate function
	socksMux   sync.Mutex
	httpMux    sync.Mutex
	redirMux   sync.Mutex
	tproxyMux  sync.Mutex
	mixedMux   sync.Mutex
	tunnelMux  sync.Mutex
	inboundMux sync.Mutex
	tunMux     sync.Mutex
	ssMux      sync.Mutex
	vmessMux   sync.Mutex
	tuicMux    sync.Mutex

	LastTunConf  LC.Tun
	LastTuicConf LC.TuicServer
)

type Ports struct {
	Port              int    `json:"port"`
	SocksPort         int    `json:"socks-port"`
	RedirPort         int    `json:"redir-port"`
	TProxyPort        int    `json:"tproxy-port"`
	MixedPort         int    `json:"mixed-port"`
	ShadowSocksConfig string `json:"ss-config"`
	VmessConfig       string `json:"vmess-config"`
}

func GetTunConf() LC.Tun {
	if tunLister == nil {
		return LastTunConf
	}
	return tunLister.Config()
}

func GetTuicConf() LC.TuicServer {
	if tuicListener == nil {
		return LC.TuicServer{Enable: false}
	}
	return tuicListener.Config()
}

func AllowLan() bool {
	return allowLan
}

func BindAddress() string {
	return bindAddress
}

func SetAllowLan(al bool) {
	allowLan = al
}

func SetBindAddress(host string) {
	bindAddress = host
}

func ReCreateHTTP(port int, tunnel C.Tunnel) {
	httpMux.Lock()
	defer httpMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start HTTP server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if httpListener != nil {
		if httpListener.RawAddress() == addr {
			return
		}
		httpListener.Close()
		httpListener = nil
	}

	if portIsZero(addr) {
		return
	}

	httpListener, err = http.New(addr, tunnel)
	if err != nil {
		log.Errorln("Start HTTP server error: %s", err.Error())
		return
	}

	log.Infoln("HTTP proxy listening at: %s", httpListener.Address())
}

func ReCreateSocks(port int, tunnel C.Tunnel) {
	socksMux.Lock()
	defer socksMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start SOCKS server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if socksListener != nil {
		if socksListener.RawAddress() != addr {
			socksListener.Close()
			socksListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}

	if socksUDPListener != nil {
		if socksUDPListener.RawAddress() != addr {
			socksUDPListener.Close()
			socksUDPListener = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return
	}

	if portIsZero(addr) {
		return
	}

	tcpListener, err := socks.New(addr, tunnel)
	if err != nil {
		return
	}

	udpListener, err := socks.NewUDP(addr, tunnel)
	if err != nil {
		tcpListener.Close()
		return
	}

	socksListener = tcpListener
	socksUDPListener = udpListener

	log.Infoln("SOCKS proxy listening at: %s", socksListener.Address())
}

func ReCreateRedir(port int, tunnel C.Tunnel) {
	redirMux.Lock()
	defer redirMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Redir server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if redirListener != nil {
		if redirListener.RawAddress() == addr {
			return
		}
		redirListener.Close()
		redirListener = nil
	}

	if redirUDPListener != nil {
		if redirUDPListener.RawAddress() == addr {
			return
		}
		redirUDPListener.Close()
		redirUDPListener = nil
	}

	if portIsZero(addr) {
		return
	}

	redirListener, err = redir.New(addr, tunnel)
	if err != nil {
		return
	}

	redirUDPListener, err = tproxy.NewUDP(addr, tunnel)
	if err != nil {
		log.Warnln("Failed to start Redir UDP Listener: %s", err)
	}

	log.Infoln("Redirect proxy listening at: %s", redirListener.Address())
}

func ReCreateShadowSocks(shadowSocksConfig string, tunnel C.Tunnel) {
	ssMux.Lock()
	defer ssMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start ShadowSocks server error: %s", err.Error())
		}
	}()

	var ssConfig LC.ShadowsocksServer
	if addr, cipher, password, err := embedSS.ParseSSURL(shadowSocksConfig); err == nil {
		ssConfig = LC.ShadowsocksServer{
			Enable:   len(shadowSocksConfig) > 0,
			Listen:   addr,
			Password: password,
			Cipher:   cipher,
			Udp:      true,
		}
	}

	shouldIgnore := false

	if shadowSocksListener != nil {
		if shadowSocksListener.Config() != ssConfig.String() {
			shadowSocksListener.Close()
			shadowSocksListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return
	}

	if !ssConfig.Enable {
		return
	}

	listener, err := sing_shadowsocks.New(ssConfig, tunnel)
	if err != nil {
		return
	}

	shadowSocksListener = listener

	for _, addr := range shadowSocksListener.AddrList() {
		log.Infoln("ShadowSocks proxy listening at: %s", addr.String())
	}
	return
}

func ReCreateVmess(vmessConfig string, tunnel C.Tunnel) {
	vmessMux.Lock()
	defer vmessMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Vmess server error: %s", err.Error())
		}
	}()

	var vsConfig LC.VmessServer
	if addr, username, password, err := sing_vmess.ParseVmessURL(vmessConfig); err == nil {
		vsConfig = LC.VmessServer{
			Enable: len(vmessConfig) > 0,
			Listen: addr,
			Users:  []LC.VmessUser{{Username: username, UUID: password, AlterID: 1}},
		}
	}

	shouldIgnore := false

	if vmessListener != nil {
		if vmessListener.Config() != vsConfig.String() {
			vmessListener.Close()
			vmessListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return
	}

	if !vsConfig.Enable {
		return
	}

	listener, err := sing_vmess.New(vsConfig, tunnel)
	if err != nil {
		return
	}

	vmessListener = listener

	for _, addr := range vmessListener.AddrList() {
		log.Infoln("Vmess proxy listening at: %s", addr.String())
	}
	return
}

func ReCreateTuic(config LC.TuicServer, tunnel C.Tunnel) {
	tuicMux.Lock()
	defer func() {
		LastTuicConf = config
		tuicMux.Unlock()
	}()
	shouldIgnore := false

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Tuic server error: %s", err.Error())
		}
	}()

	if tuicListener != nil {
		if tuicListener.Config().String() != config.String() {
			tuicListener.Close()
			tuicListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return
	}

	if !config.Enable {
		return
	}

	listener, err := tuic.New(config, tunnel)
	if err != nil {
		return
	}

	tuicListener = listener

	for _, addr := range tuicListener.AddrList() {
		log.Infoln("Tuic proxy listening at: %s", addr.String())
	}
	return
}

func ReCreateTProxy(port int, tunnel C.Tunnel) {
	tproxyMux.Lock()
	defer tproxyMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start TProxy server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if tproxyListener != nil {
		if tproxyListener.RawAddress() == addr {
			return
		}
		tproxyListener.Close()
		tproxyListener = nil
	}

	if tproxyUDPListener != nil {
		if tproxyUDPListener.RawAddress() == addr {
			return
		}
		tproxyUDPListener.Close()
		tproxyUDPListener = nil
	}

	if portIsZero(addr) {
		return
	}

	tproxyListener, err = tproxy.New(addr, tunnel)
	if err != nil {
		return
	}

	tproxyUDPListener, err = tproxy.NewUDP(addr, tunnel)
	if err != nil {
		log.Warnln("Failed to start TProxy UDP Listener: %s", err)
	}

	log.Infoln("TProxy server listening at: %s", tproxyListener.Address())
}

func ReCreateMixed(port int, tunnel C.Tunnel) {
	mixedMux.Lock()
	defer mixedMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Mixed(http+socks) server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if mixedListener != nil {
		if mixedListener.RawAddress() != addr {
			mixedListener.Close()
			mixedListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}
	if mixedUDPLister != nil {
		if mixedUDPLister.RawAddress() != addr {
			mixedUDPLister.Close()
			mixedUDPLister = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return
	}

	if portIsZero(addr) {
		return
	}

	mixedListener, err = mixed.New(addr, tunnel)
	if err != nil {
		return
	}

	mixedUDPLister, err = socks.NewUDP(addr, tunnel)
	if err != nil {
		mixedListener.Close()
		return
	}

	log.Infoln("Mixed(http+socks) proxy listening at: %s", mixedListener.Address())
}

func ReCreateTun(tunConf LC.Tun, tunnel C.Tunnel) {
	tunConf.Sort()

	tunMux.Lock()
	defer func() {
		LastTunConf = tunConf
		tunMux.Unlock()
	}()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start TUN listening error: %s", err.Error())
			tunConf.Enable = false
		}
	}()

	if tunConf.Equal(LastTunConf) {
		if tunLister != nil {
			tunLister.FlushDefaultInterface()
		}
		return
	}

	closeTunListener()

	if !tunConf.Enable {
		return
	}

	lister, err := sing_tun.New(tunConf, tunnel)
	if err != nil {
		return
	}
	tunLister = lister

	log.Infoln("[TUN] Tun adapter listening at: %s", tunLister.Address())
}

func PatchTunnel(tunnels []LC.Tunnel, tunnel C.Tunnel) {
	tunnelMux.Lock()
	defer tunnelMux.Unlock()

	type addrProxy struct {
		network string
		addr    string
		target  string
		proxy   string
	}

	tcpOld := lo.Map(
		lo.Keys(tunnelTCPListeners),
		func(key string, _ int) addrProxy {
			parts := strings.Split(key, "/")
			return addrProxy{
				network: "tcp",
				addr:    parts[0],
				target:  parts[1],
				proxy:   parts[2],
			}
		},
	)
	udpOld := lo.Map(
		lo.Keys(tunnelUDPListeners),
		func(key string, _ int) addrProxy {
			parts := strings.Split(key, "/")
			return addrProxy{
				network: "udp",
				addr:    parts[0],
				target:  parts[1],
				proxy:   parts[2],
			}
		},
	)
	oldElm := lo.Union(tcpOld, udpOld)

	newElm := lo.FlatMap(
		tunnels,
		func(tunnel LC.Tunnel, _ int) []addrProxy {
			return lo.Map(
				tunnel.Network,
				func(network string, _ int) addrProxy {
					return addrProxy{
						network: network,
						addr:    tunnel.Address,
						target:  tunnel.Target,
						proxy:   tunnel.Proxy,
					}
				},
			)
		},
	)

	needClose, needCreate := lo.Difference(oldElm, newElm)

	for _, elm := range needClose {
		key := fmt.Sprintf("%s/%s/%s", elm.addr, elm.target, elm.proxy)
		if elm.network == "tcp" {
			tunnelTCPListeners[key].Close()
			delete(tunnelTCPListeners, key)
		} else {
			tunnelUDPListeners[key].Close()
			delete(tunnelUDPListeners, key)
		}
	}

	for _, elm := range needCreate {
		key := fmt.Sprintf("%s/%s/%s", elm.addr, elm.target, elm.proxy)
		if elm.network == "tcp" {
			l, err := LT.New(elm.addr, elm.target, elm.proxy, tunnel)
			if err != nil {
				log.Errorln("Start tunnel %s error: %s", elm.target, err.Error())
				continue
			}
			tunnelTCPListeners[key] = l
			log.Infoln("Tunnel(tcp/%s) proxy %s listening at: %s", elm.target, elm.proxy, tunnelTCPListeners[key].Address())
		} else {
			l, err := LT.NewUDP(elm.addr, elm.target, elm.proxy, tunnel)
			if err != nil {
				log.Errorln("Start tunnel %s error: %s", elm.target, err.Error())
				continue
			}
			tunnelUDPListeners[key] = l
			log.Infoln("Tunnel(udp/%s) proxy %s listening at: %s", elm.target, elm.proxy, tunnelUDPListeners[key].Address())
		}
	}
}

func PatchInboundListeners(newListenerMap map[string]C.InboundListener, tunnel C.Tunnel, dropOld bool) {
	inboundMux.Lock()
	defer inboundMux.Unlock()

	for name, newListener := range newListenerMap {
		if oldListener, ok := inboundListeners[name]; ok {
			if !oldListener.Config().Equal(newListener.Config()) {
				_ = oldListener.Close()
			} else {
				continue
			}
		}
		if err := newListener.Listen(tunnel); err != nil {
			log.Errorln("Listener %s listen err: %s", name, err.Error())
			continue
		}
		inboundListeners[name] = newListener
	}

	if dropOld {
		for name, oldListener := range inboundListeners {
			if _, ok := newListenerMap[name]; !ok {
				_ = oldListener.Close()
				delete(inboundListeners, name)
			}
		}
	}
}

// GetPorts return the ports of proxy servers
func GetPorts() *Ports {
	ports := &Ports{}

	if httpListener != nil {
		_, portStr, _ := net.SplitHostPort(httpListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.Port = port
	}

	if socksListener != nil {
		_, portStr, _ := net.SplitHostPort(socksListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.SocksPort = port
	}

	if redirListener != nil {
		_, portStr, _ := net.SplitHostPort(redirListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.RedirPort = port
	}

	if tproxyListener != nil {
		_, portStr, _ := net.SplitHostPort(tproxyListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.TProxyPort = port
	}

	if mixedListener != nil {
		_, portStr, _ := net.SplitHostPort(mixedListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.MixedPort = port
	}

	if shadowSocksListener != nil {
		ports.ShadowSocksConfig = shadowSocksListener.Config()
	}

	if vmessListener != nil {
		ports.VmessConfig = vmessListener.Config()
	}

	return ports
}

func portIsZero(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return true
	}
	return false
}

func genAddr(host string, port int, allowLan bool) string {
	if allowLan {
		if host == "*" {
			return fmt.Sprintf(":%d", port)
		}
		return fmt.Sprintf("%s:%d", host, port)
	}

	return fmt.Sprintf("127.0.0.1:%d", port)
}

func closeTunListener() {
	if tunLister != nil {
		tunLister.Close()
		tunLister = nil
	}
}

func Cleanup() {
	closeTunListener()
}
