package sniffer

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
	"github.com/metacubex/mihomo/log"
)

var (
	ErrorUnsupportedSniffer = errors.New("unsupported sniffer")
	ErrorSniffFailed        = errors.New("all sniffer failed")
	ErrNoClue               = errors.New("not enough information for making a decision")
)

type Dispatcher struct {
	enable          bool
	sniffers        map[sniffer.Sniffer]SnifferConfig
	forceDomain     []C.DomainMatcher
	skipSrcAddress  []C.IpMatcher
	skipDstAddress  []C.IpMatcher
	skipDomain      []C.DomainMatcher
	skipList        *lru.LruCache[netip.AddrPort, uint8]
	forceDnsMapping bool
	parsePureIp     bool
}

func (sd *Dispatcher) shouldOverride(metadata *C.Metadata) bool {
	for _, matcher := range sd.skipDstAddress {
		if matcher.MatchIp(metadata.DstIP) {
			return false
		}
	}
	for _, matcher := range sd.skipSrcAddress {
		if matcher.MatchIp(metadata.SrcIP) {
			return false
		}
	}
	if metadata.Host == "" && sd.parsePureIp {
		return true
	}
	if metadata.DNSMode == C.DNSMapping && sd.forceDnsMapping {
		return true
	}
	for _, matcher := range sd.forceDomain {
		if matcher.MatchDomain(metadata.Host) {
			return true
		}
	}
	return false
}

func (sd *Dispatcher) UDPSniff(packet C.PacketAdapter) bool {
	metadata := packet.Metadata()
	if sd.shouldOverride(metadata) {
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
func (sd *Dispatcher) TCPSniff(conn *N.BufferedConn, metadata *C.Metadata) bool {
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

		dst := metadata.AddrPort()
		if count, ok := sd.skipList.Get(dst); ok && count > 5 {
			log.Debugln("[Sniffer] Skip sniffing[%s] due to multiple failures", dst)
			return false
		}

		host, err := sd.sniffDomain(conn, metadata)
		if err != nil {
			sd.cacheSniffFailed(metadata)
			log.Debugln("[Sniffer] All sniffing sniff failed with from [%s:%d] to [%s:%d]", metadata.SrcIP, metadata.SrcPort, metadata.String(), metadata.DstPort)
			return false
		}

		for _, matcher := range sd.skipDomain {
			if matcher.MatchDomain(host) {
				log.Debugln("[Sniffer] Skip sni[%s]", host)
				return false
			}
		}

		sd.skipList.Delete(dst)

		sd.replaceDomain(metadata, host, overrideDest)
		return true
	}
	return false
}

func (sd *Dispatcher) replaceDomain(metadata *C.Metadata, host string, overrideDest bool) {
	metadata.SniffHost = host
	if overrideDest {
		log.Debugln("[Sniffer] Sniff %s [%s]-->[%s] success, replace domain [%s]-->[%s]",
			metadata.NetWork,
			metadata.SourceDetail(),
			metadata.RemoteAddress(),
			metadata.Host, host)
		metadata.Host = host
	}
	metadata.DNSMode = C.DNSNormal
}

func (sd *Dispatcher) Enable() bool {
	return sd != nil && sd.enable
}

func (sd *Dispatcher) sniffDomain(conn *N.BufferedConn, metadata *C.Metadata) (string, error) {
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

func (sd *Dispatcher) cacheSniffFailed(metadata *C.Metadata) {
	dst := metadata.AddrPort()
	sd.skipList.Compute(dst, func(oldValue uint8, loaded bool) (newValue uint8, delete bool) {
		if oldValue <= 5 {
			oldValue++
		}
		return oldValue, false
	})
}

type Config struct {
	Enable          bool
	Sniffers        map[sniffer.Type]SnifferConfig
	ForceDomain     []C.DomainMatcher
	SkipSrcAddress  []C.IpMatcher
	SkipDstAddress  []C.IpMatcher
	SkipDomain      []C.DomainMatcher
	ForceDnsMapping bool
	ParsePureIp     bool
}

func NewDispatcher(snifferConfig *Config) (*Dispatcher, error) {
	dispatcher := Dispatcher{
		enable:          snifferConfig.Enable,
		forceDomain:     snifferConfig.ForceDomain,
		skipSrcAddress:  snifferConfig.SkipSrcAddress,
		skipDstAddress:  snifferConfig.SkipDstAddress,
		skipDomain:      snifferConfig.SkipDomain,
		skipList:        lru.New(lru.WithSize[netip.AddrPort, uint8](128), lru.WithAge[netip.AddrPort, uint8](600)),
		forceDnsMapping: snifferConfig.ForceDnsMapping,
		parsePureIp:     snifferConfig.ParsePureIp,
		sniffers:        make(map[sniffer.Sniffer]SnifferConfig, len(snifferConfig.Sniffers)),
	}

	for snifferName, config := range snifferConfig.Sniffers {
		s, err := NewSniffer(snifferName, config)
		if err != nil {
			log.Errorln("Sniffer name[%s] is error", snifferName)
			return &Dispatcher{enable: false}, err
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
