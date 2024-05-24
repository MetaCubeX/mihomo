package listener

import (
	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"strconv"

	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/log"
)

func ReCreateMixedTls(wanInput *inbound.WanInput, tunnel C.Tunnel) {

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start tls server error: %s", err.Error())
		}
	}()

	addr := ":" + strconv.Itoa(wanInput.Port)
	if portIsZero(addr) {
		return
	}

	//mixedListener, err = mixed.New(addr, tcpIn)
	mixed.InitSShServer(tunnel)
	mixedTlsListener, err := mixed.NewTls(addr, wanInput, tunnel)
	if err != nil {
		return
	}

	// mixedTlsUDPLister, err = socks.NewUDP(addr, udpIn)
	// if err != nil {
	// 	mixedTlsListener.Close()
	// 	return
	// }

	log.Infoln("wan proxy listening at: %s", mixedTlsListener.Address())
}
