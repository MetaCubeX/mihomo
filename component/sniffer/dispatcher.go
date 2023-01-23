package sniffer

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/utils"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/sniffer"
	"github.com/Dreamacro/clash/log"
)

var (
	ErrorUnsupportedSniffer = errors.New("unsupported sniffer")
	ErrorSniffFailed        = errors.New("all sniffer failed")
	ErrNoClue               = errors.New("not enough information for making a decision")
)

var Dispatcher *SnifferDispatcher

type SnifferDispatcher struct {
	enable bool

	sniffers []sniffer.Sniffer

	forceDomain *trie.DomainTrie[struct{}]
	skipSNI     *trie.DomainTrie[struct{}]
	portRanges  *[]utils.Range[uint16]
	skipList    *cache.LruCache[string, uint8]
	rwMux       sync.RWMutex

	forceDnsMapping bool
	parsePureIp     bool
}

func (sd *SnifferDispatcher) TCPSniff(conn net.Conn, metadata *C.Metadata) {
	bufConn, ok := conn.(*N.BufferedConn)
	if !ok {
		return
	}

	if (metadata.Host == "" && sd.parsePureIp) || sd.forceDomain.Search(metadata.Host) != nil || (metadata.DNSMode == C.DNSMapping && sd.forceDnsMapping) {
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

		sd.rwMux.RLock()
		dst := fmt.Sprintf("%s:%s", metadata.DstIP, metadata.DstPort)
		if count, ok := sd.skipList.Get(dst); ok && count > 5 {
			log.Debugln("[Sniffer] Skip sniffing[%s] due to multiple failures", dst)
			defer sd.rwMux.RUnlock()
			return
		}
		sd.rwMux.RUnlock()

		if host, err := sd.sniffDomain(bufConn, metadata); err != nil {
			sd.cacheSniffFailed(metadata)
			log.Debugln("[Sniffer] All sniffing sniff failed with from [%s:%s] to [%s:%s]", metadata.SrcIP, metadata.SrcPort, metadata.String(), metadata.DstPort)
			return
		} else {
			if sd.skipSNI.Search(host) != nil {
				log.Debugln("[Sniffer] Skip sni[%s]", host)
				return
			}

			sd.rwMux.RLock()
			sd.skipList.Delete(dst)
			sd.rwMux.RUnlock()

			sd.replaceDomain(metadata, host)
		}
	}
}

func (sd *SnifferDispatcher) replaceDomain(metadata *C.Metadata, host string) {
	dstIP := ""
	if metadata.DstIP.IsValid() {
		dstIP = metadata.DstIP.String()
	}
	originHost := metadata.Host
	if originHost != host {
		log.Infoln("[Sniffer] Sniff TCP [%s]-->[%s:%s] success, replace domain [%s]-->[%s]",
			metadata.SourceDetail(),
			dstIP, metadata.DstPort,
			metadata.Host, host)
	} else {
		log.Debugln("[Sniffer] Sniff TCP [%s]-->[%s:%s] success, replace domain [%s]-->[%s]",
			metadata.SourceDetail(),
			dstIP, metadata.DstPort,
			metadata.Host, host)
	}

	metadata.Host = host
	metadata.DNSMode = C.DNSNormal
}

func (sd *SnifferDispatcher) Enable() bool {
	return sd.enable
}

func (sd *SnifferDispatcher) sniffDomain(conn *N.BufferedConn, metadata *C.Metadata) (string, error) {
	for _, s := range sd.sniffers {
		if s.SupportNetwork() == C.TCP {
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			_, err := conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
			if err != nil {
				_, ok := err.(*net.OpError)
				if ok {
					sd.cacheSniffFailed(metadata)
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

			host, err := s.SniffTCP(bytes)
			if err != nil {
				//log.Debugln("[Sniffer] [%s] Sniff data failed %s", s.Protocol(), metadata.DstIP)
				continue
			}

			_, err = netip.ParseAddr(host)
			if err == nil {
				//log.Debugln("[Sniffer] [%s] Sniff data failed %s", s.Protocol(), metadata.DstIP)
				continue
			}

			return host, nil
		}
	}

	return "", ErrorSniffFailed
}

func (sd *SnifferDispatcher) cacheSniffFailed(metadata *C.Metadata) {
	sd.rwMux.Lock()
	dst := fmt.Sprintf("%s:%s", metadata.DstIP, metadata.DstPort)
	count, _ := sd.skipList.Get(dst)
	if count <= 5 {
		count++
	}
	sd.skipList.Set(dst, count)
	sd.rwMux.Unlock()
}

func NewCloseSnifferDispatcher() (*SnifferDispatcher, error) {
	dispatcher := SnifferDispatcher{
		enable: false,
	}

	return &dispatcher, nil
}

func NewSnifferDispatcher(needSniffer []sniffer.Type, forceDomain *trie.DomainTrie[struct{}],
	skipSNI *trie.DomainTrie[struct{}], ports *[]utils.Range[uint16],
	forceDnsMapping bool, parsePureIp bool) (*SnifferDispatcher, error) {
	dispatcher := SnifferDispatcher{
		enable:          true,
		forceDomain:     forceDomain,
		skipSNI:         skipSNI,
		portRanges:      ports,
		skipList:        cache.New[string, uint8](cache.WithSize[string, uint8](128), cache.WithAge[string, uint8](600)),
		forceDnsMapping: forceDnsMapping,
		parsePureIp:     parsePureIp,
	}

	for _, snifferName := range needSniffer {
		s, err := NewSniffer(snifferName)
		if err != nil {
			log.Errorln("Sniffer name[%s] is error", snifferName)
			return &SnifferDispatcher{enable: false}, err
		}

		dispatcher.sniffers = append(dispatcher.sniffers, s)
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
