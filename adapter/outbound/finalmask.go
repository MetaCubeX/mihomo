package outbound

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// randomInRange picks a uniformly-distributed integer in [r.Start, r.End].
// Shared by fragment and header-custom layers.
func randomInRange(r utils.Range[int]) int {
	start := r.Start()
	end := r.End()
	span := end - start
	if span <= 0 {
		return start
	}
	return start + rand.IntN(span+1)
}

// FinalMaskOption mirrors the XTLS FinalMask configuration. See
// https://xtls.github.io/ru/config/transports/finalmask.html
//
// Only TCP layers are implemented in this iteration. UDP and QUICParams are
// parsed (so configs validate) but emit a warning and are otherwise ignored.
type FinalMaskOption struct {
	TCP        []FinalMaskLayer `proxy:"tcp,omitempty"`
	UDP        []FinalMaskLayer `proxy:"udp,omitempty"`
	QUICParams any              `proxy:"quic-params,omitempty"`
}

// FinalMaskLayer is the union of every layer's settings, discriminated by Type.
// The decoder cannot handle map[string]any, so we keep all possible fields
// side-by-side and let the per-type parser pick the relevant ones.
type FinalMaskLayer struct {
	Type     string                 `proxy:"type"`
	Settings FinalMaskLayerSettings `proxy:"settings,omitempty"`
}

// FinalMaskLayerSettings is the union struct. Only the subset matching the
// parent layer's Type is consulted at parse time.
type FinalMaskLayerSettings struct {
	// fragment
	Packets  string   `proxy:"packets,omitempty"`   // "tlshello" | "1-3"
	Lengths  []string `proxy:"lengths,omitempty"`   // per-fragment ranges, last applies to all remaining
	Delays   []string `proxy:"delays,omitempty"`    // per-fragment delays, last applies to all remaining
	MaxSplit string   `proxy:"max-split,omitempty"` // Int32Range, max fragments per packet, 0 = unlimited

	// header-custom
	Clients [][]HeaderCustomPacket `proxy:"clients,omitempty"`
}

// finalMaskLayer is the parsed, ready-to-apply form of one mask layer.
type finalMaskLayer interface {
	wrap(net.Conn) net.Conn
}

type finalMaskConfig struct {
	tcpLayers []finalMaskLayer
}

func (o *FinalMaskOption) Parse() *finalMaskConfig {
	if o == nil {
		return nil
	}
	if len(o.TCP) == 0 && len(o.UDP) == 0 && o.QUICParams == nil {
		return nil
	}

	if len(o.UDP) > 0 {
		log.Warnln("finalmask: UDP layers are not yet implemented, ignoring %d layer(s)", len(o.UDP))
	}
	if o.QUICParams != nil {
		log.Warnln("finalmask: quicParams is not yet implemented, ignoring")
	}
	if len(o.TCP) == 0 {
		return nil
	}

	layers := make([]finalMaskLayer, 0, len(o.TCP))
	for i, raw := range o.TCP {
		layer, err := raw.parse()
		if err != nil {
			log.Warnln("finalmask: skipping tcp[%d]: %v", i, err)
			continue
		}
		layers = append(layers, layer)
	}
	if len(layers) == 0 {
		return nil
	}
	return &finalMaskConfig{tcpLayers: layers}
}

func (l FinalMaskLayer) parse() (finalMaskLayer, error) {
	switch l.Type {
	case "fragment":
		return parseFragmentLayer(l.Settings)
	case "header-custom":
		return parseHeaderCustomLayer(l.Settings)
	default:
		return nil, fmt.Errorf("unknown layer type %q", l.Type)
	}
}

// finalMaskDialer wraps a C.Dialer and applies the TCP layer chain to every
// dialed connection. Per the spec, layers[0] is the innermost (closest to the
// real conn); each subsequent layer wraps the previous result.
type finalMaskDialer struct {
	C.Dialer
	cfg *finalMaskConfig
}

func newFinalMaskDialer(inner C.Dialer, cfg *finalMaskConfig) C.Dialer {
	return &finalMaskDialer{Dialer: inner, cfg: cfg}
}

func (d *finalMaskDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	for _, layer := range d.cfg.tcpLayers {
		conn = layer.wrap(conn)
	}
	return conn, nil
}

func (d *finalMaskDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return d.Dialer.ListenPacket(ctx, network, address, rAddrPort)
}
