package lwip

import (
	"io"
	"net"
	"sync"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/dev"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	"github.com/Dreamacro/clash/log"
	"github.com/yaling888/go-lwip"
)

type lwipAdapter struct {
	device    dev.TunDevice
	lwipStack golwip.LWIPStack
	lock      sync.Mutex
	mtu       int
	stackName string
	dnsListen string
	autoRoute bool
}

func NewAdapter(device dev.TunDevice, conf config.Tun, mtu int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.TunAdapter, error) {
	adapter := &lwipAdapter{
		device:    device,
		mtu:       mtu,
		stackName: conf.Stack,
		dnsListen: conf.DNSListen,
		autoRoute: conf.AutoRoute,
	}

	adapter.lock.Lock()
	defer adapter.lock.Unlock()

	dnsHost, _, err := net.SplitHostPort(conf.DNSListen)
	if err != nil {
		return nil, err
	}

	dnsIP := net.ParseIP(dnsHost)

	golwip.RegisterOutputFn(func(data []byte) (int, error) {
		return device.Write(data)
	})

	// Setup TCP/IP stack.
	lwipStack := golwip.NewLWIPStack(mtu)
	adapter.lwipStack = lwipStack

	golwip.RegisterDnsHandler(NewDnsHandler())
	golwip.RegisterTCPConnHandler(NewTCPHandler(dnsIP, tcpIn))
	golwip.RegisterUDPConnHandler(NewUDPHandler(dnsIP, udpIn))

	// Copy packets from tun device to lwip stack, it's the loop.
	go func(lwipStack golwip.LWIPStack, device dev.TunDevice, mtu int) {
		_, err := io.CopyBuffer(lwipStack.(io.Writer), device, make([]byte, mtu))
		if err != nil {
			log.Errorln("copying data failed: %v", err)
		}
	}(lwipStack, device, mtu)

	return adapter, nil
}

func (l *lwipAdapter) Stack() string {
	return l.stackName
}

func (l *lwipAdapter) AutoRoute() bool {
	return l.autoRoute
}

func (l *lwipAdapter) DNSListen() string {
	return l.dnsListen
}

func (l *lwipAdapter) Close() {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.stopLocked()
}

func (l *lwipAdapter) stopLocked() {
	if l.lwipStack != nil {
		l.lwipStack.Close()
	}

	if l.device != nil {
		_ = l.device.Close()
	}

	l.lwipStack = nil
	l.device = nil
}
