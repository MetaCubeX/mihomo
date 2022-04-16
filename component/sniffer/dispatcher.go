package sniffer

import (
	"errors"
	"github.com/Dreamacro/clash/component/trie"
	"net"

	CN "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var (
	ErrorUnsupportedSniffer = errors.New("unsupported sniffer")
	ErrorSniffFailed        = errors.New("all sniffer failed")
)

var Dispatcher SnifferDispatcher

type SnifferDispatcher struct {
	enable            bool
	force             bool
	sniffers          []C.Sniffer
	reverseDomainTree *trie.DomainTrie[struct{}]
	tcpHandler        func(conn *CN.BufferedConn, metadata *C.Metadata)
}

func (sd *SnifferDispatcher) forceReplace(conn *CN.BufferedConn, metadata *C.Metadata) {
	host, err := sd.sniffDomain(conn, metadata)
	if err != nil {
		log.Debugln("[Sniffer]All sniffing sniff failed with from [%s:%s] to [%s:%s]", metadata.SrcIP, metadata.SrcPort, metadata.DstIP, metadata.DstPort)
		return
	} else {
		if sd.force && sd.inReverse(host) {
			log.Debugln("[Sniffer]Skip replace host:%s", host)
			return
		}
	}

	sd.replaceDomain(metadata, host)
}

func (sd *SnifferDispatcher) replace(conn *CN.BufferedConn, metadata *C.Metadata) {
	if metadata.Host != "" && sd.inReverse(metadata.Host) {
		log.Debugln("[Sniffer]Skip Sniff domain:%s", metadata.Host)
		return
	}

	host, err := sd.sniffDomain(conn, metadata)
	if err != nil {
		log.Debugln("[Sniffer]All sniffing sniff failed with from [%s:%s] to [%s:%s]", metadata.SrcIP, metadata.SrcPort, metadata.DstIP, metadata.DstPort)
		return
	}

	sd.replaceDomain(metadata, host)
}

func (sd *SnifferDispatcher) TCPSniff(conn net.Conn, metadata *C.Metadata) {
	bufConn, ok := conn.(*CN.BufferedConn)
	if !ok {
		return
	}

	sd.tcpHandler(bufConn, metadata)
}

func (sd *SnifferDispatcher) inReverse(host string) bool {
	return sd.reverseDomainTree != nil && sd.reverseDomainTree.Search(host) != nil
}

func (sd *SnifferDispatcher) replaceDomain(metadata *C.Metadata, host string) {
	log.Debugln("[Sniffer]Sniff TCP [%s:%s]-->[%s:%s] success, replace domain [%s]-->[%s]",
		metadata.SrcIP, metadata.SrcPort,
		metadata.DstIP, metadata.DstPort,
		metadata.Host, host)

	metadata.AddrType = C.AtypDomainName
	metadata.Host = host
	if resolver.FakeIPEnabled() {
		metadata.DNSMode = C.DNSFakeIP
	} else {
		metadata.DNSMode = C.DNSMapping
	}

	resolver.InsertHostByIP(metadata.DstIP, host)
	metadata.DstIP = nil
}

func (sd *SnifferDispatcher) Enable() bool {
	return sd.enable
}

func (sd *SnifferDispatcher) sniffDomain(conn *CN.BufferedConn, metadata *C.Metadata) (string, error) {
	for _, sniffer := range sd.sniffers {
		if sniffer.SupportNetwork() == C.TCP {
			_, err := conn.Peek(1)
			if err != nil {
				return "", err
			}

			bufferedLen := conn.Buffered()
			bytes, err := conn.Peek(bufferedLen)
			if err != nil {
				log.Debugln("[Sniffer] the data length not enough")
				continue
			}

			host, err := sniffer.SniffTCP(bytes)
			if err != nil {
				log.Debugln("[Sniffer][%s] Sniff data failed %s", sniffer.Protocol(), metadata.DstIP)
				continue
			}

			return host, nil
		}
	}

	return "", ErrorSniffFailed
}

func NewCloseSnifferDispatcher() (*SnifferDispatcher, error) {
	dispatcher := SnifferDispatcher{
		enable: false,
	}

	return &dispatcher, nil
}

func NewSnifferDispatcher(needSniffer []C.SnifferType, force bool, reverses *trie.DomainTrie[struct{}]) (*SnifferDispatcher, error) {
	dispatcher := SnifferDispatcher{
		enable:            true,
		force:             force,
		reverseDomainTree: reverses,
	}

	for _, snifferName := range needSniffer {
		sniffer, err := NewSniffer(snifferName)
		if err != nil {
			log.Errorln("Sniffer name[%s] is error", snifferName)
			return &SnifferDispatcher{enable: false}, err
		}

		dispatcher.sniffers = append(dispatcher.sniffers, sniffer)
	}

	if force {
		dispatcher.tcpHandler = dispatcher.forceReplace
	} else {
		dispatcher.tcpHandler = dispatcher.replace
	}

	return &dispatcher, nil
}

func NewSniffer(name C.SnifferType) (C.Sniffer, error) {
	switch name {
	case C.TLS:
		return &TLSSniffer{}, nil
	default:
		return nil, ErrorUnsupportedSniffer
	}
}
