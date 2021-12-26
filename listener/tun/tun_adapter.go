package tun

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/dev"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system"
	"github.com/Dreamacro/clash/log"
)

// New create TunAdapter
func New(conf config.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.TunAdapter, error) {
	tunAddress := "198.18.0.1"
	autoRoute := conf.AutoRoute
	stack := conf.Stack
	var tunAdapter ipstack.TunAdapter

	device, err := dev.OpenTunDevice(tunAddress, autoRoute)
	if err != nil {
		for i := 1; i < 3; i++ {
			time.Sleep(time.Second * 1)
			device, err = dev.OpenTunDevice(tunAddress, autoRoute)
			if err == nil {
				break
			}
		}

		if err != nil {
			return nil, fmt.Errorf("can't open tun: %v", err)
		}
	}

	mtu, err := device.MTU()
	if err != nil {
		_ = device.Close()
		return nil, errors.New("unable to get device mtu")
	}

	if strings.EqualFold(stack, "system") {
		tunAdapter, err = system.NewAdapter(device, conf, mtu, tunAddress, tunAddress, func() {}, tcpIn, udpIn)
	} else if strings.EqualFold(stack, "gvisor") {
		tunAdapter, err = gvisor.NewAdapter(device, conf, tcpIn, udpIn)
	} else {
		err = fmt.Errorf("can not support tun ip stack: %s, only support \"lwip\" \"system\" and \"gvisor\"", stack)
	}

	if err != nil {
		_ = device.Close()
		return nil, err
	}

	log.Infoln("Tun adapter listening at: %s(%s), mtu: %d, auto route: %v, ip stack: %s", device.Name(), tunAddress, mtu, autoRoute, stack)
	return tunAdapter, nil
}
