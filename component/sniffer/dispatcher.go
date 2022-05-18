package sniffer

import (
	"errors"
	"github.com/Dreamacro/clash/constant/sniffer"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/Dreamacro/clash/component/trie"

	CN "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/utils"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var (
	ErrorUnsupportedSniffer = errors.New("unsupported sniffer")
	ErrorSniffFailed        = errors.New("all sniffer failed")
	ErrNoClue               = errors.New("not enough information for making a decision")
)

var Dispatcher SnifferDispatcher

type (
	SnifferDispatcher struct {
		enable bool

		sniffers []sniffer.Sniffer

		foreDomain *trie.DomainTrie[bool]
		skipSNI    *trie.DomainTrie[bool]
		portRanges *[]utils.Range[uint16]
	}
)

func (sd *SnifferDispatcher) TCPSniff(conn net.Conn, metadata *C.Metadata) {
	bufConn, ok := conn.(*CN.BufferedConn)
	if !ok {
		return
	}

	if metadata.Host == "" || sd.foreDomain.Search(metadata.Host) != nil {
		port, err := strconv.ParseUint(metadata.DstPort, 10, 16)
		if err != nil {
			log.Debugln("[Sniffer] Dst port is error")
			return
		}

		inWhitelist := false
		for _, portRange := range *sd.portRanges {
			if portRange.Contains(uint16(port)) {
				inWhitelist = true
				break
			}
		}

		if !inWhitelist {
			return
		}

		if host, err := sd.sniffDomain(bufConn, metadata); err != nil {
			log.Debugln("[Sniffer] All sniffing sniff failed with from [%s:%s] to [%s:%s]", metadata.SrcIP, metadata.SrcPort, metadata.String(), metadata.DstPort)
			return
		} else {
			if sd.skipSNI.Search(host) != nil {
				log.Debugln("[Sniffer] Skip sni[%s]", host)
				return
			}

			sd.replaceDomain(metadata, host)
		}
	}
}

func (sd *SnifferDispatcher) replaceDomain(metadata *C.Metadata, host string) {
	log.Debugln("[Sniffer] Sniff TCP [%s:%s]-->[%s:%s] success, replace domain [%s]-->[%s]",
		metadata.SrcIP, metadata.SrcPort,
		metadata.DstIP, metadata.DstPort,
		metadata.Host, host)

	metadata.AddrType = C.AtypDomainName
	metadata.Host = host
	metadata.DNSMode = C.DNSMapping
	resolver.InsertHostByIP(metadata.DstIP, host)
}

func (sd *SnifferDispatcher) Enable() bool {
	return sd.enable
}

func (sd *SnifferDispatcher) sniffDomain(conn *CN.BufferedConn, metadata *C.Metadata) (string, error) {
	for _, sniffer := range sd.sniffers {
		if sniffer.SupportNetwork() == C.TCP {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, err := conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
			if err != nil {
				_, ok := err.(*net.OpError)
				if ok {
					log.Errorln("[Sniffer] [%s] may not have any sent data, Consider adding skip", metadata.DstIP.String())
					_ = conn.Close()
				}

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
				//log.Debugln("[Sniffer] [%s] Sniff data failed %s", sniffer.Protocol(), metadata.DstIP)
				continue
			}

			_, err = netip.ParseAddr(host)
			if err == nil {
				//log.Debugln("[Sniffer] [%s] Sniff data failed %s", sniffer.Protocol(), metadata.DstIP)
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

func NewSnifferDispatcher(needSniffer []sniffer.Type, forceDomain *trie.DomainTrie[bool],
	skipSNI *trie.DomainTrie[bool], ports *[]utils.Range[uint16]) (*SnifferDispatcher, error) {
	dispatcher := SnifferDispatcher{
		enable:     true,
		foreDomain: forceDomain,
		skipSNI:    skipSNI,
		portRanges: ports,
	}

	for _, snifferName := range needSniffer {
		sniffer, err := NewSniffer(snifferName)
		if err != nil {
			log.Errorln("Sniffer name[%s] is error", snifferName)
			return &SnifferDispatcher{enable: false}, err
		}

		dispatcher.sniffers = append(dispatcher.sniffers, sniffer)
	}

	return &dispatcher, nil
}

func NewSniffer(name sniffer.Type) (sniffer.Sniffer, error) {
	switch name {
	case sniffer.TLS:
		return &TLSSniffer{}, nil
	case sniffer.HTTP:
		return &HTTPSniffer{}, nil
	default:
		return nil, ErrorUnsupportedSniffer
	}
}
