package sniffer

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/sing/common/metadata"

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

// maxSniffBufferSize bounds the per-connection read-ahead memory used by TCP
// sniffing. 64 KiB covers the HTTP/2 preface and several default-sized frames
// while keeping lengths read from untrusted protocol headers bounded.
const maxSniffBufferSize = 64 * 1024

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
	return sd.forceSniff(metadata)
}

func (sd *Dispatcher) forceSniff(metadata *C.Metadata) bool {
	for _, matcher := range sd.forceDomain {
		if matcher.MatchDomain(metadata.Host) {
			return true
		}
	}
	return false
}

// UDPSniff is called when a UDP NAT is created and passed the first initialization packet.
// It may return a wrapped packetSender if the sniffer process needs to wait for multiple packets.
// This function must be non-blocking, and any blocking operations should be done in the wrapped packetSender.
func (sd *Dispatcher) UDPSniff(packet C.PacketAdapter, packetSender C.PacketSender) C.PacketSender {
	metadata := packet.Metadata()
	if sd.shouldOverride(metadata) {
		for current, config := range sd.sniffers {
			if current.SupportNetwork() == C.UDP || current.SupportNetwork() == C.ALLNet {
				inWhitelist := current.SupportPort(metadata.DstPort)
				overrideDest := config.OverrideDest

				if inWhitelist {
					replaceDomain := func(metadata *C.Metadata, host string) {
						if sd.domainCanReplace(host) {
							replaceDomain(metadata, host, overrideDest)
						} else {
							log.Debugln("[Sniffer] Skip sni[%s]", host)
						}
					}

					if wrapable, ok := current.(sniffer.MultiPacketSniffer); ok {
						return wrapable.WrapperSender(packetSender, replaceDomain)
					}

					host, err := current.SniffData(packet.Data())
					if err != nil {
						continue
					}

					replaceDomain(metadata, host)
					return packetSender
				}
			}
		}
	}

	return packetSender
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
		forceSniffer := sd.forceSniff(metadata)

		dst := metadata.AddrPort()
		if !forceSniffer {
			if count, ok := sd.skipList.Get(dst); ok && count > 5 {
				log.Debugln("[Sniffer] Skip sniffing[%s] due to multiple failures", dst)
				return false
			}
		}

		host, err := sd.sniffDomain(conn, metadata)
		if err != nil {
			if !forceSniffer {
				sd.cacheSniffFailed(metadata)
			}
			log.Debugln("[Sniffer] All sniffing sniff failed with from [%s:%d] to [%s:%d]", metadata.SrcIP, metadata.SrcPort, metadata.String(), metadata.DstPort)
			return false
		}

		if !sd.domainCanReplace(host) {
			log.Debugln("[Sniffer] Skip sni[%s]", host)
			return false
		}

		sd.skipList.Delete(dst)

		replaceDomain(metadata, host, overrideDest)
		return true
	}
	return false
}

func replaceDomain(metadata *C.Metadata, host string, overrideDest bool) {
	metadata.SniffHost = host
	if overrideDest {
		log.Debugln("[Sniffer] Sniff %s [%s]-->[%s] success, replace domain [%s]-->[%s]",
			metadata.NetWork,
			metadata.SourceDetail(),
			metadata.RemoteAddress(),
			metadata.Host, host)
		metadata.Host = host
		metadata.DstIP = netip.Addr{}
	}
	metadata.DNSMode = C.DNSNormal
}

func (sd *Dispatcher) domainCanReplace(host string) bool {
	if host == "." || !metadata.IsDomainName(host) {
		return false
	}
	for _, matcher := range sd.skipDomain {
		if matcher.MatchDomain(host) {
			return false
		}
	}
	return true
}

func (sd *Dispatcher) Enable() bool {
	return sd != nil && sd.enable
}

func (sd *Dispatcher) sniffDomain(conn *N.BufferedConn, metadata *C.Metadata) (string, error) {
	//defer func(start time.Time) {
	//	log.Debugln("[Sniffer] [%s] Sniffing took %s", metadata.DstIP, time.Since(start))
	//}(time.Now())

	for s := range sd.sniffers {
		if s.SupportNetwork() == C.TCP && s.SupportPort(metadata.DstPort) {
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			_, err := conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
			if err != nil {
				_, ok := err.(*net.OpError)
				if ok {
					sd.cacheSniffFailed(metadata)
					log.Errorln("[Sniffer] [%s] [%s] may not have any sent data, Consider adding skip", metadata.DstIP, s.Protocol())
					_ = conn.Close()
				}

				return "", err
			}

			// Feed the sniffer until it reaches a verdict. A sniffer that needs more
			// data returns errNeedAtLeastData with the total length it wants;
			// protocols like HTTP/2 discover that length incrementally (preface,
			// then frame header, then payload), so several rounds may be required.
			var host string // the verdict, read after the loop
			want := conn.Buffered()
			// one budget for all rounds, so they can't add up
			deadline := time.Now().Add(1 * time.Second)
			for {
				var data []byte
				_ = conn.SetReadDeadline(deadline)
				data, err = conn.Peek(want)
				_ = conn.SetReadDeadline(time.Time{})
				if err != nil {
					log.Debugln("[Sniffer] [%s] [%s] the data length not enough, error: %v", metadata.DstIP, s.Protocol(), err)
					break
				}
				// Peeking fills the buffer from the underlying conn, which usually
				// yields a whole segment rather than exactly the requested bytes.
				// Hand over everything that arrived: sniffers that can't predict how
				// much they need (HTTP/1 headers) then make progress per segment
				// instead of per byte.
				if buffered := conn.Buffered(); buffered > len(data) {
					if all, e := conn.Peek(buffered); e == nil {
						data = all
					}
				}

				host, err = s.SniffData(data)
				var need *errNeedAtLeastData
				if !errors.As(err, &need) {
					break
				}
				// Only keep going while more data can actually be obtained: the
				// request has to exceed what the sniffer already saw and fit in the
				// budget. Since a retry always asks for more than is buffered, it
				// waits on the conn instead of spinning on the same data.
				if need.length <= len(data) || !time.Now().Before(deadline) {
					break
				}
				// Request enough capacity for the next retry. Grow rounds capacity up
				// geometrically, while this power-of-two limit keeps automatic allocation
				// bounded when a protocol advertises a much larger length.
				growTo := need.length
				if growTo > maxSniffBufferSize {
					growTo = maxSniffBufferSize
				}
				conn.Grow(growTo)
				//log.Debugln("[Sniffer] [%s] [%s] %v, got length: %d, want: %d", metadata.DstIP, s.Protocol(), need, len(data), need.length)
				want = need.length
			}
			if err != nil {
				//log.Debugln("[Sniffer] [%s] [%s] Sniff data failed, error: %v", metadata.DstIP, s.Protocol(), err)
				continue
			}

			_, err = netip.ParseAddr(host)
			if err == nil {
				//log.Debugln("[Sniffer] [%s] [%s] Sniff data failed, got host [%s]", metadata.DstIP, s.Protocol(), host)
				continue
			}

			//log.Debugln("[Sniffer] [%s] [%s] Sniffed [%s]", metadata.DstIP, s.Protocol(), host)
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
		return NewQUICSniffer(snifferConfig)
	default:
		return nil, ErrorUnsupportedSniffer
	}
}
