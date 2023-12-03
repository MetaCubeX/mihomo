package sniffer

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
	"github.com/metacubex/mihomo/log"
)

var (
	ErrorUnsupportedSniffer = errors.New("unsupported sniffer")
	ErrorSniffFailed        = errors.New("all sniffer failed")
	ErrNoClue               = errors.New("not enough information for making a decision")
)

var Dispatcher *SnifferDispatcher

type SnifferDispatcher struct {
	enable          bool
	sniffers        map[sniffer.Sniffer]SnifferConfig
	forceDomain     *trie.DomainSet
	skipSNI         *trie.DomainSet
	skipList        *lru.LruCache[string, uint8]
	rwMux           sync.RWMutex
	forceDnsMapping bool
	parsePureIp     bool
}

func (sd *SnifferDispatcher) shouldOverride(metadata *C.Metadata) bool {
	return (metadata.Host == "" && sd.parsePureIp) ||
		sd.forceDomain.Has(metadata.Host) ||
		(metadata.DNSMode == C.DNSMapping && sd.forceDnsMapping)
}

func (sd *SnifferDispatcher) UDPSniff(packet C.PacketAdapter) bool {
	metadata := packet.Metadata()

	if sd.shouldOverride(packet.Metadata()) {
		for sniffer, config := range sd.sniffers {
			if sniffer.SupportNetwork() == C.UDP || sniffer.SupportNetwork() == C.ALLNet {
				inWhitelist := sniffer.SupportPort(metadata.DstPort)
				overrideDest := config.OverrideDest

				if inWhitelist {
					host, err := sniffer.SniffData(packet.Data())
					if err != nil {
						continue
					}

					sd.replaceDomain(metadata, host, overrideDest)
					return true
				}
			}
		}
	}

	return false
}

// TCPSniff returns true if the connection is sniffed to have a domain
func (sd *SnifferDispatcher) TCPSniff(conn *N.BufferedConn, metadata *C.Metadata) bool {
	if sd.shouldOverride(metadata) {
		inWhitelist := false
		overrideDest := false
		for sniffer, config := range sd.sniffers {
			if sniffer.SupportNetwork() == C.TCP || sniffer.SupportNetwork() == C.ALLNet {
				inWhitelist = sniffer.SupportPort(metadata.DstPort)
				if inWhitelist {
					overrideDest = config.OverrideDest
					break
				}
			}
		}

		if !inWhitelist {
			return false
		}

		sd.rwMux.RLock()
		dst := fmt.Sprintf("%s:%d", metadata.DstIP, metadata.DstPort)
		if count, ok := sd.skipList.Get(dst); ok && count > 5 {
			log.Debugln("[Sniffer] Skip sniffing[%s] due to multiple failures", dst)
			defer sd.rwMux.RUnlock()
			return false
		}
		sd.rwMux.RUnlock()

		if host, err := sd.sniffDomain(conn, metadata); err != nil {
			sd.cacheSniffFailed(metadata)
			log.Debugln("[Sniffer] All sniffing sniff failed with from [%s:%d] to [%s:%d]", metadata.SrcIP, metadata.SrcPort, metadata.String(), metadata.DstPort)
			return false
		} else {
			if sd.skipSNI.Has(host) {
				log.Debugln("[Sniffer] Skip sni[%s]", host)
				return false
			}

			sd.rwMux.RLock()
			sd.skipList.Delete(dst)
			sd.rwMux.RUnlock()

			sd.replaceDomain(metadata, host, overrideDest)
			return true
		}
	}
	return false
}

func (sd *SnifferDispatcher) replaceDomain(metadata *C.Metadata, host string, overrideDest bool) {
	// show log early, since the following code may mutate `metadata.Host`
	log.Debugln("[Sniffer] Sniff %s [%s]-->[%s] success, replace domain [%s]-->[%s]",
		metadata.NetWork,
		metadata.SourceDetail(),
		metadata.RemoteAddress(),
		metadata.Host, host)
	metadata.SniffHost = host
	if overrideDest {
		metadata.Host = host
	}
	metadata.DNSMode = C.DNSNormal
}

func (sd *SnifferDispatcher) Enable() bool {
	return sd.enable
}

func (sd *SnifferDispatcher) sniffDomain(conn *N.BufferedConn, metadata *C.Metadata) (string, error) {
	for s := range sd.sniffers {
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

			host, err := s.SniffData(bytes)
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
	dst := fmt.Sprintf("%s:%d", metadata.DstIP, metadata.DstPort)
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

func NewSnifferDispatcher(snifferConfig map[sniffer.Type]SnifferConfig,
	forceDomain *trie.DomainSet, skipSNI *trie.DomainSet,
	forceDnsMapping bool, parsePureIp bool) (*SnifferDispatcher, error) {
	dispatcher := SnifferDispatcher{
		enable:          true,
		forceDomain:     forceDomain,
		skipSNI:         skipSNI,
		skipList:        lru.New(lru.WithSize[string, uint8](128), lru.WithAge[string, uint8](600)),
		forceDnsMapping: forceDnsMapping,
		parsePureIp:     parsePureIp,
		sniffers:        make(map[sniffer.Sniffer]SnifferConfig, 0),
	}

	for snifferName, config := range snifferConfig {
		s, err := NewSniffer(snifferName, config)
		if err != nil {
			log.Errorln("Sniffer name[%s] is error", snifferName)
			return &SnifferDispatcher{enable: false}, err
		}
		dispatcher.sniffers[s] = config
	}

	return &dispatcher, nil
}

func NewSniffer(name sniffer.Type, snifferConfig SnifferConfig) (sniffer.Sniffer, error) {
	switch name {
	case sniffer.TLS:
		return NewTLSSniffer(snifferConfig)
	case sniffer.HTTP:
		return NewHTTPSniffer(snifferConfig)
	case sniffer.QUIC:
		return NewQuicSniffer(snifferConfig)
	default:
		return nil, ErrorUnsupportedSniffer
	}
}
