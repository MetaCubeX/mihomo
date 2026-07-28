package sniffer

import (
	"bufio"
	"errors"
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
	sniffers        []configuredSniffer
	forceDomain     []C.DomainMatcher
	skipSrcAddress  []C.IpMatcher
	skipDstAddress  []C.IpMatcher
	skipDomain      []C.DomainMatcher
	skipList        *lru.LruCache[netip.AddrPort, uint8]
	forceDnsMapping bool
	parsePureIp     bool
}

// configuredSniffer keeps protocol-specific behavior and policy together so
// the successful sniffer's policy is applied to its result.
type configuredSniffer struct {
	sniffer.Sniffer
	config SnifferConfig
}

func (s configuredSniffer) supportsNetwork(network C.NetWork) bool {
	supported := s.SupportNetwork()
	return supported == network || supported == C.ALLNet
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
		for _, current := range sd.sniffers {
			if current.supportsNetwork(C.UDP) {
				inWhitelist := current.SupportPort(metadata.DstPort)
				overrideDest := current.config.OverrideDest

				if inWhitelist {
					replaceDomain := func(metadata *C.Metadata, host string) {
						if sd.domainCanReplace(host) {
							replaceDomain(metadata, host, overrideDest)
						} else {
							log.Debugln("[Sniffer] Skip sni[%s]", host)
						}
					}

					if wrapable, ok := current.Sniffer.(sniffer.MultiPacketSniffer); ok {
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
		for _, current := range sd.sniffers {
			if current.supportsNetwork(C.TCP) {
				inWhitelist = current.SupportPort(metadata.DstPort)
				if inWhitelist {
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

		host, config, err := sd.sniffDomain(conn, metadata)
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

		replaceDomain(metadata, host, config.OverrideDest)
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
	if !isValidSniffHost(host) {
		return false
	}
	for _, matcher := range sd.skipDomain {
		if matcher.MatchDomain(host) {
			return false
		}
	}
	return true
}

func isValidSniffHost(host string) bool {
	return host != "." && metadata.IsDomainName(host)
}

func (sd *Dispatcher) Enable() bool {
	return sd != nil && sd.enable
}

func (sd *Dispatcher) sniffDomain(conn *N.BufferedConn, metadata *C.Metadata) (string, SnifferConfig, error) {
	//defer func(start time.Time) {
	//	log.Debugln("[Sniffer] [%s] Sniffing took %s", metadata.DstIP, time.Since(start))
	//}(time.Now())

	type candidate struct {
		configuredSniffer
		want int // minimum buffer length required before the next attempt
	}
	// Keep the configured order while discarding protocols that cannot apply to
	// this connection. The remaining entries carry their own OverrideDest policy.
	candidates := make([]candidate, 0, len(sd.sniffers))
	for _, current := range sd.sniffers {
		if current.supportsNetwork(C.TCP) && current.SupportPort(metadata.DstPort) {
			candidates = append(candidates, candidate{configuredSniffer: current, want: 1})
		}
	}
	if len(candidates) == 0 {
		return "", SnifferConfig{}, ErrorSniffFailed
	}

	// The initial byte has its own one-second window because client data may not
	// have arrived yet. Peek usually buffers the whole available segment.
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err := conn.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		// The caller owns failure accounting and the connection lifetime. No
		// initial data can be valid for a server-first protocol, so sniffing must
		// not close the connection merely because this deadline expired.
		log.Debugln("[Sniffer] [%s] the data length not enough, error: %v", metadata.DstIP, err)
		return "", SnifferConfig{}, err
	}

	// After the initial read, all candidates and retries share a fresh budget.
	deadline := time.Now().Add(1 * time.Second)
	want := conn.Buffered()
	for len(candidates) > 0 {
		// Reject an unmet oversized request before Grow or Peek. Otherwise Peek
		// fills the bounded buffer before reporting that the request cannot fit.
		if want > maxSniffBufferSize && want > conn.Buffered() {
			return "", SnifferConfig{}, bufio.ErrBufferFull
		}
		conn.Grow(want)

		_ = conn.SetReadDeadline(deadline)
		_, err = conn.Peek(want)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			// Initial data was received, so leave the connection open for the caller
			// to continue relaying without a sniffed domain.
			log.Debugln("[Sniffer] [%s] the data length not enough, error: %v", metadata.DstIP, err)
			return "", SnifferConfig{}, err
		}

		// The first Peek may buffer more than requested. Everything reported by
		// Buffered is already available, so this second Peek cannot read or fail.
		data, _ := conn.Peek(conn.Buffered())

		// Compact the active set in place. A candidate remains active only while
		// it has a larger input requirement; permanent failures and
		// invalid successful results are discarded.
		remaining := candidates[:0]
		nextWant := 0
		for _, current := range candidates {
			// Another candidate may have requested the shorter read that produced
			// this snapshot. Leave larger requests paused until enough data exists.
			if current.want <= len(data) {
				host, err := current.SniffData(data)
				if err == nil {
					if isValidSniffHost(host) {
						return host, current.config, nil
					}
					continue
				}

				// Only an explicit request beyond this snapshot can make progress in
				// another round. All other errors permanently reject the candidate.
				var need *errNeedAtLeastData
				if !errors.As(err, &need) || need.length <= len(data) {
					continue
				}
				current.want = need.length
			}

			remaining = append(remaining, current)
			if nextWant == 0 || current.want < nextWant {
				nextWant = current.want
			}
		}

		candidates = remaining
		want = nextWant
	}

	return "", SnifferConfig{}, ErrorSniffFailed
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
		sniffers:        make([]configuredSniffer, 0, len(snifferConfig.Sniffers)),
	}

	// Configuration is map-based, but protocol order must remain deterministic
	// when multiple sniffers cover the same port.
	for _, snifferName := range sniffer.List {
		config, loaded := snifferConfig.Sniffers[snifferName]
		if !loaded {
			continue
		}
		s, err := NewSniffer(snifferName, config)
		if err != nil {
			log.Errorln("Sniffer name[%s] is error", snifferName)
			return &Dispatcher{enable: false}, err
		}
		dispatcher.sniffers = append(dispatcher.sniffers, configuredSniffer{Sniffer: s, config: config})
	}
	// Entries absent from sniffer.List were not constructed by the ordered pass
	// above. Preserve the previous behavior of rejecting such configurations.
	if len(dispatcher.sniffers) != len(snifferConfig.Sniffers) {
		for snifferName := range snifferConfig.Sniffers {
			found := false
			for _, supported := range sniffer.List {
				if snifferName == supported {
					found = true
					break
				}
			}
			if !found {
				log.Errorln("Sniffer name[%s] is error", snifferName)
				return &Dispatcher{enable: false}, ErrorUnsupportedSniffer
			}
		}
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
