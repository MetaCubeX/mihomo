package gvisor

import (
	"fmt"

	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	// defaultTimeToLive specifies the default TTL used by stack.
	defaultTimeToLive uint8 = 64

	// ipForwardingEnabled is the value used by stack to enable packet
	// forwarding between NICs.
	ipForwardingEnabled = true

	// icmpBurst is the default number of ICMP messages that can be sent in
	// a single burst.
	icmpBurst = 50

	// icmpLimit is the default maximum number of ICMP messages permitted
	// by this rate limiter.
	icmpLimit rate.Limit = 1000

	// tcpCongestionControl is the congestion control algorithm used by
	// stack. ccReno is the default option in gVisor stack.
	tcpCongestionControlAlgorithm = "reno" // "reno" or "cubic"

	// tcpDelayEnabled is the value used by stack to enable or disable
	// tcp delay option. Disable Nagle's algorithm here by default.
	tcpDelayEnabled = false

	// tcpModerateReceiveBufferEnabled is the value used by stack to
	// enable or disable tcp receive buffer auto-tuning option.
	tcpModerateReceiveBufferEnabled = true

	// tcpSACKEnabled is the value used by stack to enable or disable
	// tcp selective ACK.
	tcpSACKEnabled = true

	// tcpRecovery is the loss detection algorithm used by TCP.
	tcpRecovery = tcpip.TCPRACKLossDetection

	// tcpMinBufferSize is the smallest size of a send/recv buffer.
	tcpMinBufferSize = tcp.MinBufferSize // 4 KiB

	// tcpMaxBufferSize is the maximum permitted size of a send/recv buffer.
	tcpMaxBufferSize = tcp.MaxBufferSize // 4 MiB

	// tcpDefaultBufferSize is the default size of the send/recv buffer for
	// a transport endpoint.
	tcpDefaultBufferSize = 212 << 10 // 212 KiB
)

type Option func(*gvStack) error

// WithDefault sets all default values for stack.
func WithDefault() Option {
	return func(s *gvStack) error {
		opts := []Option{
			WithDefaultTTL(defaultTimeToLive),
			WithForwarding(ipForwardingEnabled),

			// Config default stack ICMP settings.
			WithICMPBurst(icmpBurst), WithICMPLimit(icmpLimit),

			// We expect no packet loss, therefore we can bump buffers.
			// Too large buffers thrash cache, so there is little point
			// in too large buffers.
			//
			// Ref: https://github.com/cloudflare/slirpnetstack/blob/master/stack.go
			WithTCPBufferSizeRange(tcpMinBufferSize, tcpDefaultBufferSize, tcpMaxBufferSize),

			WithTCPCongestionControl(tcpCongestionControlAlgorithm),
			WithTCPDelay(tcpDelayEnabled),

			// Receive Buffer Auto-Tuning Option, see:
			// https://github.com/google/gvisor/issues/1666
			WithTCPModerateReceiveBuffer(tcpModerateReceiveBufferEnabled),

			// TCP selective ACK Option, see:
			// https://tools.ietf.org/html/rfc2018
			WithTCPSACKEnabled(tcpSACKEnabled),

			// TCPRACKLossDetection: indicates RACK is used for loss detection and
			// recovery.
			//
			// TCPRACKStaticReoWnd: indicates the reordering window should not be
			// adjusted when DSACK is received.
			//
			// TCPRACKNoDupTh: indicates RACK should not consider the classic three
			// duplicate acknowledgements rule to mark the segments as lost. This
			// is used when reordering is not detected.
			WithTCPRecovery(tcpRecovery),
		}

		for _, opt := range opts {
			if err := opt(s); err != nil {
				return err
			}
		}

		return nil
	}
}

// WithDefaultTTL sets the default TTL used by stack.
func WithDefaultTTL(ttl uint8) Option {
	return func(s *gvStack) error {
		opt := tcpip.DefaultTTLOption(ttl)
		if err := s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set ipv4 default TTL: %s", err)
		}
		if err := s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set ipv6 default TTL: %s", err)
		}
		return nil
	}
}

// WithForwarding sets packet forwarding between NICs for IPv4 & IPv6.
func WithForwarding(v bool) Option {
	return func(s *gvStack) error {
		if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, v); err != nil {
			return fmt.Errorf("set ipv4 forwarding: %s", err)
		}
		if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, v); err != nil {
			return fmt.Errorf("set ipv6 forwarding: %s", err)
		}
		return nil
	}
}

// WithICMPBurst sets the number of ICMP messages that can be sent
// in a single burst.
func WithICMPBurst(burst int) Option {
	return func(s *gvStack) error {
		s.SetICMPBurst(burst)
		return nil
	}
}

// WithICMPLimit sets the maximum number of ICMP messages permitted
// by rate limiter.
func WithICMPLimit(limit rate.Limit) Option {
	return func(s *gvStack) error {
		s.SetICMPLimit(limit)
		return nil
	}
}

// WithTCPBufferSizeRange sets the receive and send buffer size range for TCP.
func WithTCPBufferSizeRange(a, b, c int) Option {
	return func(s *gvStack) error {
		rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: a, Default: b, Max: c}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt); err != nil {
			return fmt.Errorf("set TCP receive buffer size range: %s", err)
		}
		sndOpt := tcpip.TCPSendBufferSizeRangeOption{Min: a, Default: b, Max: c}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt); err != nil {
			return fmt.Errorf("set TCP send buffer size range: %s", err)
		}
		return nil
	}
}

// WithTCPCongestionControl sets the current congestion control algorithm.
func WithTCPCongestionControl(cc string) Option {
	return func(s *gvStack) error {
		opt := tcpip.CongestionControlOption(cc)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP congestion control algorithm: %s", err)
		}
		return nil
	}
}

// WithTCPDelay enables or disables Nagle's algorithm in TCP.
func WithTCPDelay(v bool) Option {
	return func(s *gvStack) error {
		opt := tcpip.TCPDelayEnabled(v)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP delay: %s", err)
		}
		return nil
	}
}

// WithTCPModerateReceiveBuffer sets receive buffer moderation for TCP.
func WithTCPModerateReceiveBuffer(v bool) Option {
	return func(s *gvStack) error {
		opt := tcpip.TCPModerateReceiveBufferOption(v)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP moderate receive buffer: %s", err)
		}
		return nil
	}
}

// WithTCPSACKEnabled sets the SACK option for TCP.
func WithTCPSACKEnabled(v bool) Option {
	return func(s *gvStack) error {
		opt := tcpip.TCPSACKEnabled(v)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP SACK: %s", err)
		}
		return nil
	}
}

// WithTCPRecovery sets the recovery option for TCP.
func WithTCPRecovery(v tcpip.TCPRecovery) Option {
	return func(s *gvStack) error {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &v); err != nil {
			return fmt.Errorf("set TCP Recovery: %s", err)
		}
		return nil
	}
}
