package tunnel

import (
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
)

// The inbound address survives both sniffing and rule resolution. Only Target
// is sent to an outbound; Route may contain an IP obtained solely to match rules.
type udpDestination struct {
	Origin  M.Socksaddr
	Route   *C.Metadata
	Target  M.Socksaddr
	direct  bool
	fixedIP bool
	key     udpPacketKey
}

func newUDPDestination(metadata *C.Metadata, allowRemote bool, key string) *udpDestination {
	route := metadata.Clone()
	fixMetadata(route)
	origin := M.ParseSocksaddrHostPort(route.String(), route.DstPort)
	target := M.ParseSocksaddrHostPort(route.Pure().String(), route.DstPort)
	route.UDP = &C.UDPRequest{
		Target: target, AllowRemote: allowRemote, SessionKey: key,
	}
	return &udpDestination{
		Origin: origin, Route: route, Target: target,
		direct:  origin.IsIP() && !resolver.IsFakeIP(origin.Addr),
		fixedIP: target.IsIP() && route.Pure().Host == "" && route.Host != "",
		key:     udpPacketKeyFromMetadata(metadata),
	}
}

func (d *udpDestination) prepare() error {
	metadata := d.Route
	if metadata.UDP.Target != d.Target {
		d.fixedIP = false
	}
	lookup := needLookupIP(metadata)
	fake := lookup && resolver.IsFakeIP(metadata.DstIP)
	if err := preHandleMetadata(metadata); err != nil {
		return err
	}
	if lookup && !fake && metadata.Host != "" {
		d.fixedIP = true
	}
	// Later packets do not run rules again, but hosts must apply to every target,
	// including SpecialProxy requests which bypass the normal rule matcher.
	if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
		ip, _ := node.RandIP()
		setUDPTarget(metadata, M.SocksaddrFrom(ip, metadata.DstPort))
	}
	d.Target = metadata.UDP.Target
	return nil
}

func (d *udpDestination) dialMetadata() *C.Metadata {
	metadata := d.Route.Pure().Clone()
	d.Target = metadata.UDP.Target
	if d.Target.IsIP() && d.fixedIP {
		// A sniff-only name can reset DNSMode, but must not undo the original
		// Pure() IP target. Other local snapshots retain their adapter's resolver
		// semantics, including hosts preference and protocol-specific DNS.
		metadata.Host = ""
		metadata.DstIP = d.Target.Addr
	}
	return metadata
}

func setUDPTarget(metadata *C.Metadata, target M.Socksaddr) {
	if metadata.UDP != nil {
		request := *metadata.UDP
		request.Target = target
		metadata.UDP = &request
	}
}

// Sniffers receive their own routing view; they never mutate the packet's
// original destination, which also remains the identity of the NAT target.
type udpSniffPacket struct {
	C.PacketAdapter
	metadata *C.Metadata
}

func (p udpSniffPacket) Metadata() *C.Metadata { return p.metadata }
