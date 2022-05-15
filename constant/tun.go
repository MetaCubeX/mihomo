package constant

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

var StackTypeMapping = map[string]TUNStack{
	strings.ToUpper(TunGvisor.String()): TunGvisor,
	strings.ToUpper(TunSystem.String()): TunSystem,
}

const (
	TunGvisor TUNStack = iota
	TunSystem
)

type TUNStack int

// UnmarshalYAML unserialize TUNStack with yaml
func (e *TUNStack) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		return err
	}
	mode, exist := StackTypeMapping[strings.ToUpper(tp)]
	if !exist {
		return errors.New("invalid tun stack")
	}
	*e = mode
	return nil
}

// MarshalYAML serialize TUNStack with yaml
func (e TUNStack) MarshalYAML() (any, error) {
	return e.String(), nil
}

// UnmarshalJSON unserialize TUNStack with json
func (e *TUNStack) UnmarshalJSON(data []byte) error {
	var tp string
	_ = json.Unmarshal(data, &tp)
	mode, exist := StackTypeMapping[strings.ToUpper(tp)]
	if !exist {
		return errors.New("invalid tun stack")
	}
	*e = mode
	return nil
}

// MarshalJSON serialize TUNStack with json
func (e TUNStack) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (e TUNStack) String() string {
	switch e {
	case TunGvisor:
		return "gVisor"
	case TunSystem:
		return "System"
	default:
		return "unknown"
	}
}

type DNSAddrPort struct {
	netip.AddrPort
}

func (p *DNSAddrPort) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*p = DNSAddrPort{}
		return nil
	}

	addrPort := string(text)
	if strings.HasPrefix(addrPort, "any") {
		_, port, _ := strings.Cut(addrPort, "any")
		addrPort = "0.0.0.0" + port
	}

	ap, err := netip.ParseAddrPort(addrPort)
	*p = DNSAddrPort{AddrPort: ap}
	return err
}

func (p DNSAddrPort) String() string {
	addrPort := p.AddrPort.String()
	if p.AddrPort.Addr().IsUnspecified() {
		addrPort = "any:" + strconv.Itoa(int(p.AddrPort.Port()))
	}
	return addrPort
}

type DNSUrl struct {
	Network  string
	AddrPort DNSAddrPort
}

func (d *DNSUrl) UnmarshalYAML(unmarshal func(any) error) error {
	var text string
	if err := unmarshal(&text); err != nil {
		return err
	}

	text = strings.ToLower(text)
	network := "udp"
	if before, after, found := strings.Cut(text, "://"); found {
		network = before
		text = after
	}

	if network != "udp" && network != "tcp" {
		return errors.New("invalid dns url schema")
	}

	ap := &DNSAddrPort{}
	if err := ap.UnmarshalText([]byte(text)); err != nil {
		return err
	}

	*d = DNSUrl{Network: network, AddrPort: *ap}

	return nil
}

func (d DNSUrl) MarshalYAML() (any, error) {
	return d.String(), nil
}

func (d *DNSUrl) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}

	text = strings.ToLower(text)
	network := "udp"
	if before, after, found := strings.Cut(text, "://"); found {
		network = before
		text = after
	}

	if network != "udp" && network != "tcp" {
		return errors.New("invalid dns url schema")
	}

	ap := &DNSAddrPort{}
	if err := ap.UnmarshalText([]byte(text)); err != nil {
		return err
	}

	*d = DNSUrl{Network: network, AddrPort: *ap}

	return nil
}

func (d DNSUrl) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d DNSUrl) String() string {
	return d.Network + "://" + d.AddrPort.String()
}

func RemoveDuplicateDNSUrl(slice []DNSUrl) []DNSUrl {
	slices.SortFunc[DNSUrl](slice, func(a, b DNSUrl) bool {
		return a.Network < b.Network || (a.Network == b.Network && a.AddrPort.Addr().Less(b.AddrPort.Addr()))
	})

	return slices.CompactFunc[[]DNSUrl, DNSUrl](slice, func(a, b DNSUrl) bool {
		return a.Network == b.Network && a.AddrPort == b.AddrPort
	})
}
