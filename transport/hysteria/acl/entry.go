package acl

import (
	"errors"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"net"
	"strconv"
	"strings"
)

type Action byte
type Protocol byte

const (
	ActionDirect = Action(iota)
	ActionProxy
	ActionBlock
	ActionHijack
)

const (
	ProtocolAll = Protocol(iota)
	ProtocolTCP
	ProtocolUDP
)

var protocolPortAliases = map[string]string{
	"echo":     "*/7",
	"ftp-data": "*/20",
	"ftp":      "*/21",
	"ssh":      "*/22",
	"telnet":   "*/23",
	"domain":   "*/53",
	"dns":      "*/53",
	"http":     "*/80",
	"sftp":     "*/115",
	"ntp":      "*/123",
	"https":    "*/443",
	"quic":     "udp/443",
	"socks":    "*/1080",
}

type Entry struct {
	Action    Action
	ActionArg string
	Matcher   Matcher
}

type MatchRequest struct {
	IP     net.IP
	Domain string

	Protocol Protocol
	Port     uint16

	DB *geoip2.Reader
}

type Matcher interface {
	Match(MatchRequest) bool
}

type matcherBase struct {
	Protocol Protocol
	Port     uint16 // 0 for all ports
}

func (m *matcherBase) MatchProtocolPort(p Protocol, port uint16) bool {
	return (m.Protocol == ProtocolAll || m.Protocol == p) && (m.Port == 0 || m.Port == port)
}

func parseProtocolPort(s string) (Protocol, uint16, error) {
	if protocolPortAliases[s] != "" {
		s = protocolPortAliases[s]
	}
	if len(s) == 0 || s == "*" {
		return ProtocolAll, 0, nil
	}
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return ProtocolAll, 0, errors.New("invalid protocol/port syntax")
	}
	protocol := ProtocolAll
	switch parts[0] {
	case "tcp":
		protocol = ProtocolTCP
	case "udp":
		protocol = ProtocolUDP
	case "*":
		protocol = ProtocolAll
	default:
		return ProtocolAll, 0, errors.New("invalid protocol")
	}
	if parts[1] == "*" {
		return protocol, 0, nil
	}
	port, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return ProtocolAll, 0, errors.New("invalid port")
	}
	return protocol, uint16(port), nil
}

type netMatcher struct {
	matcherBase
	Net *net.IPNet
}

func (m *netMatcher) Match(r MatchRequest) bool {
	if r.IP == nil {
		return false
	}
	return m.Net.Contains(r.IP) && m.MatchProtocolPort(r.Protocol, r.Port)
}

type domainMatcher struct {
	matcherBase
	Domain string
	Suffix bool
}

func (m *domainMatcher) Match(r MatchRequest) bool {
	if len(r.Domain) == 0 {
		return false
	}
	domain := strings.ToLower(r.Domain)
	return (m.Domain == domain || (m.Suffix && strings.HasSuffix(domain, "."+m.Domain))) &&
		m.MatchProtocolPort(r.Protocol, r.Port)
}

type countryMatcher struct {
	matcherBase
	Country string // ISO 3166-1 alpha-2 country code, upper case
}

func (m *countryMatcher) Match(r MatchRequest) bool {
	if r.IP == nil || r.DB == nil {
		return false
	}
	c, err := r.DB.Country(r.IP)
	if err != nil {
		return false
	}
	return c.Country.IsoCode == m.Country && m.MatchProtocolPort(r.Protocol, r.Port)
}

type allMatcher struct {
	matcherBase
}

func (m *allMatcher) Match(r MatchRequest) bool {
	return m.MatchProtocolPort(r.Protocol, r.Port)
}

func (e Entry) Match(r MatchRequest) bool {
	return e.Matcher.Match(r)
}

func ParseEntry(s string) (Entry, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return Entry{}, fmt.Errorf("expected at least 2 fields, got %d", len(fields))
	}
	e := Entry{}
	action := fields[0]
	conds := fields[1:]
	switch strings.ToLower(action) {
	case "direct":
		e.Action = ActionDirect
	case "proxy":
		e.Action = ActionProxy
	case "block":
		e.Action = ActionBlock
	case "hijack":
		if len(conds) < 2 {
			return Entry{}, fmt.Errorf("hijack requires at least 3 fields, got %d", len(fields))
		}
		e.Action = ActionHijack
		e.ActionArg = conds[len(conds)-1]
		conds = conds[:len(conds)-1]
	default:
		return Entry{}, fmt.Errorf("invalid action %s", fields[0])
	}
	m, err := condsToMatcher(conds)
	if err != nil {
		return Entry{}, err
	}
	e.Matcher = m
	return e, nil
}

func condsToMatcher(conds []string) (Matcher, error) {
	if len(conds) < 1 {
		return nil, errors.New("no condition specified")
	}
	typ, args := conds[0], conds[1:]
	switch strings.ToLower(typ) {
	case "domain":
		// domain <domain> <optional: protocol/port>
		if len(args) == 0 || len(args) > 2 {
			return nil, fmt.Errorf("invalid number of arguments for domain: %d, expected 1 or 2", len(args))
		}
		mb := matcherBase{}
		if len(args) == 2 {
			protocol, port, err := parseProtocolPort(args[1])
			if err != nil {
				return nil, err
			}
			mb.Protocol = protocol
			mb.Port = port
		}
		return &domainMatcher{
			matcherBase: mb,
			Domain:      args[0],
			Suffix:      false,
		}, nil
	case "domain-suffix":
		// domain-suffix <domain> <optional: protocol/port>
		if len(args) == 0 || len(args) > 2 {
			return nil, fmt.Errorf("invalid number of arguments for domain-suffix: %d, expected 1 or 2", len(args))
		}
		mb := matcherBase{}
		if len(args) == 2 {
			protocol, port, err := parseProtocolPort(args[1])
			if err != nil {
				return nil, err
			}
			mb.Protocol = protocol
			mb.Port = port
		}
		return &domainMatcher{
			matcherBase: mb,
			Domain:      args[0],
			Suffix:      true,
		}, nil
	case "cidr":
		// cidr <cidr> <optional: protocol/port>
		if len(args) == 0 || len(args) > 2 {
			return nil, fmt.Errorf("invalid number of arguments for cidr: %d, expected 1 or 2", len(args))
		}
		mb := matcherBase{}
		if len(args) == 2 {
			protocol, port, err := parseProtocolPort(args[1])
			if err != nil {
				return nil, err
			}
			mb.Protocol = protocol
			mb.Port = port
		}
		_, ipNet, err := net.ParseCIDR(args[0])
		if err != nil {
			return nil, err
		}
		return &netMatcher{
			matcherBase: mb,
			Net:         ipNet,
		}, nil
	case "ip":
		// ip <ip> <optional: protocol/port>
		if len(args) == 0 || len(args) > 2 {
			return nil, fmt.Errorf("invalid number of arguments for ip: %d, expected 1 or 2", len(args))
		}
		mb := matcherBase{}
		if len(args) == 2 {
			protocol, port, err := parseProtocolPort(args[1])
			if err != nil {
				return nil, err
			}
			mb.Protocol = protocol
			mb.Port = port
		}
		ip := net.ParseIP(args[0])
		if ip == nil {
			return nil, fmt.Errorf("invalid ip: %s", args[0])
		}
		var ipNet *net.IPNet
		if ip.To4() != nil {
			ipNet = &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(32, 32),
			}
		} else {
			ipNet = &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(128, 128),
			}
		}
		return &netMatcher{
			matcherBase: mb,
			Net:         ipNet,
		}, nil
	case "country":
		// country <country> <optional: protocol/port>
		if len(args) == 0 || len(args) > 2 {
			return nil, fmt.Errorf("invalid number of arguments for country: %d, expected 1 or 2", len(args))
		}
		mb := matcherBase{}
		if len(args) == 2 {
			protocol, port, err := parseProtocolPort(args[1])
			if err != nil {
				return nil, err
			}
			mb.Protocol = protocol
			mb.Port = port
		}
		return &countryMatcher{
			matcherBase: mb,
			Country:     strings.ToUpper(args[0]),
		}, nil
	case "all":
		// all <optional: protocol/port>
		if len(args) > 1 {
			return nil, fmt.Errorf("invalid number of arguments for all: %d, expected 0 or 1", len(args))
		}
		mb := matcherBase{}
		if len(args) == 1 {
			protocol, port, err := parseProtocolPort(args[0])
			if err != nil {
				return nil, err
			}
			mb.Protocol = protocol
			mb.Port = port
		}
		return &allMatcher{
			matcherBase: mb,
		}, nil
	default:
		return nil, fmt.Errorf("invalid condition type: %s", typ)
	}
}
