package constant

import "fmt"

type UDPMapping uint8

const (
	UDPEndpointIndependent UDPMapping = iota
	UDPAddressDependent
	UDPAddressAndPortDependent
)

func (m UDPMapping) String() string {
	switch m {
	case UDPEndpointIndependent:
		return "endpoint-independent"
	case UDPAddressDependent:
		return "address-dependent"
	case UDPAddressAndPortDependent:
		return "address-and-port-dependent"
	default:
		return "unknown"
	}
}

func (m UDPMapping) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

func (m *UDPMapping) UnmarshalText(data []byte) error {
	switch string(data) {
	case "endpoint-independent":
		*m = UDPEndpointIndependent
	case "address-dependent":
		*m = UDPAddressDependent
	case "address-and-port-dependent":
		*m = UDPAddressAndPortDependent
	default:
		return fmt.Errorf("invalid udp-mapping: %q", data)
	}
	return nil
}
