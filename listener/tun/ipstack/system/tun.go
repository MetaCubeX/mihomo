package system

import (
	"net"
	"strconv"
	"sync"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/dev"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	"github.com/Dreamacro/clash/log"
	"github.com/kr328/tun2socket"
	"github.com/kr328/tun2socket/binding"
	"github.com/kr328/tun2socket/redirect"
)

type systemAdapter struct {
	device    dev.TunDevice
	tun       *tun2socket.Tun2Socket
	lock      sync.Mutex
	stackName string
	dnsListen string
	autoRoute bool
}

func NewAdapter(device dev.TunDevice, conf config.Tun, mtu int, gateway, mirror string, onStop func(), tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.TunAdapter, error) {

	adapter := &systemAdapter{
		device:    device,
		stackName: conf.Stack,
		dnsListen: conf.DNSListen,
		autoRoute: conf.AutoRoute,
	}

	adapter.lock.Lock()
	defer adapter.lock.Unlock()

	//adapter.stopLocked()

	dnsHost, dnsPort, err := net.SplitHostPort(conf.DNSListen)
	if err != nil {
		return nil, err
	}

	dnsP, err := strconv.Atoi(dnsPort)
	if err != nil {
		return nil, err
	}

	dnsAddr := binding.Address{
		IP:   net.ParseIP(dnsHost),
		Port: uint16(dnsP),
	}

	t := tun2socket.NewTun2Socket(device, mtu, net.ParseIP(gateway), net.ParseIP(mirror))

	t.SetAllocator(allocUDP)
	t.SetClosedHandler(onStop)
	t.SetLogger(&logger{})

	t.SetTCPHandler(func(conn net.Conn, endpoint *binding.Endpoint) {
		if shouldHijackDns(dnsAddr, endpoint.Target) {
			hijackTCPDns(conn)

			if log.Level() == log.DEBUG {
				log.Debugln("[TUN] hijack dns tcp: %s:%d", endpoint.Target.IP.String(), endpoint.Target.Port)
			}
			return
		}

		handleTCP(conn, endpoint, tcpIn)
	})
	t.SetUDPHandler(func(payload []byte, endpoint *binding.Endpoint, sender redirect.UDPSender) {
		if shouldHijackDns(dnsAddr, endpoint.Target) {
			hijackUDPDns(payload, endpoint, sender)

			if log.Level() == log.DEBUG {
				log.Debugln("[TUN] hijack dns udp: %s:%d", endpoint.Target.IP.String(), endpoint.Target.Port)
			}
			return
		}

		handleUDP(payload, endpoint, sender, udpIn)
	})

	t.Start()

	adapter.tun = t

	return adapter, nil
}

func (t *systemAdapter) Stack() string {
	return t.stackName
}

func (t *systemAdapter) AutoRoute() bool {
	return t.autoRoute
}

func (t *systemAdapter) DNSListen() string {
	return t.dnsListen
}

func (t *systemAdapter) Close() {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.stopLocked()
}

func (t *systemAdapter) stopLocked() {
	if t.tun != nil {
		t.tun.Close()
	}

	if t.device != nil {
		_ = t.device.Close()
	}

	t.tun = nil
	t.device = nil
}
