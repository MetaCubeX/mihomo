package sniffer

import (
	"errors"
	"net"

	CN "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var (
	ErrorUnsupportedSniffer = errors.New("unsupported sniffer")
)

var Dispatcher SnifferDispatcher

type SnifferDispatcher struct {
	enable   bool
	force    bool
	sniffers []C.Sniffer
}

func (sd *SnifferDispatcher) Tcp(conn net.Conn, metadata *C.Metadata) {
	bufConn, ok := conn.(*CN.BufferedConn)
	if !ok {
		return
	}

	if sd.force {
		sd.cover(bufConn, metadata)
	} else {
		if metadata.Host != "" {
			return
		}
		sd.cover(bufConn, metadata)
	}
}

func (sd *SnifferDispatcher) Enable() bool {
	return sd.enable
}

func (sd *SnifferDispatcher) cover(conn *CN.BufferedConn, metadata *C.Metadata) {
	for _, sniffer := range sd.sniffers {
		if sniffer.SupportNetwork() == C.TCP {
			_, err := conn.Peek(1)
			if err != nil {
				return
			}

			bufferedLen := conn.Buffered()
			bytes, err := conn.Peek(bufferedLen)
			if err != nil {
				log.Debugln("[Sniffer] the data lenght not enough")
				continue
			}

			host, err := sniffer.SniffTCP(bytes)
			if err != nil {
				log.Debugln("[Sniffer][%s] Sniff data failed", sniffer.Protocol())
				continue
			}
			metadata.Host = host
			metadata.AddrType = C.AtypDomainName
			log.Debugln("[Sniffer][%s] %s --> %s", sniffer.Protocol(), metadata.DstIP, metadata.Host)
			if resolver.FakeIPEnabled() {
				metadata.DNSMode = C.DNSFakeIP
			} else {
				metadata.DNSMode = C.DNSMapping
			}
			resolver.InsertHostByIP(metadata.DstIP, host)
			metadata.DstIP = nil

			break
		}
	}
}

func NewSnifferDispatcher(needSniffer []C.SnifferType, force bool) (SnifferDispatcher, error) {
	dispatcher := SnifferDispatcher{
		enable: true,
		force:  force,
	}

	for _, snifferName := range needSniffer {
		sniffer, err := NewSniffer(snifferName)
		if err != nil {
			log.Errorln("Sniffer name[%s] is error", snifferName)
			return SnifferDispatcher{enable: false}, err
		}

		dispatcher.sniffers = append(dispatcher.sniffers, sniffer)
	}

	return dispatcher, nil
}

func NewSniffer(name C.SnifferType) (C.Sniffer, error) {
	switch name {
	case C.TLS:
		return &TLSSniffer{}, nil
	default:
		return nil, ErrorUnsupportedSniffer
	}
}
