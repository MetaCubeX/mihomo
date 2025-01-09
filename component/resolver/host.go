package resolver

import (
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	_ "unsafe"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resolver/hosts"
	"github.com/metacubex/mihomo/component/trie"
	"github.com/metacubex/randv2"
)

var (
	DisableSystemHosts, _ = strconv.ParseBool(os.Getenv("DISABLE_SYSTEM_HOSTS"))
	UseSystemHosts        bool
)

type Hosts struct {
	*trie.DomainTrie[HostValue]
}

func NewHosts(hosts *trie.DomainTrie[HostValue]) Hosts {
	return Hosts{
		hosts,
	}
}

// Return the search result and whether to match the parameter `isDomain`
func (h *Hosts) Search(domain string, isDomain bool) (*HostValue, bool) {
	if value := h.DomainTrie.Search(domain); value != nil {
		hostValue := value.Data()
		for {
			if isDomain && hostValue.IsDomain {
				return &hostValue, true
			} else {
				if node := h.DomainTrie.Search(hostValue.Domain); node != nil {
					hostValue = node.Data()
				} else {
					break
				}
			}
		}
		if isDomain == hostValue.IsDomain {
			return &hostValue, true
		}

		return &hostValue, false
	}

	if !isDomain && !DisableSystemHosts && UseSystemHosts {
		addr, _ := hosts.LookupStaticHost(domain)
		if hostValue, err := NewHostValue(addr); err == nil {
			return &hostValue, true
		}
	}
	return nil, false
}

type HostValue struct {
	IsDomain bool
	IPs      []netip.Addr
	Domain   string
}

func NewHostValue(value any) (HostValue, error) {
	isDomain := true
	ips := make([]netip.Addr, 0)
	domain := ""
	if valueArr, err := utils.ToStringSlice(value); err != nil {
		return HostValue{}, err
	} else {
		if len(valueArr) > 1 {
			isDomain = false
			for _, str := range valueArr {
				if ip, err := netip.ParseAddr(str); err == nil {
					ips = append(ips, ip)
				} else {
					return HostValue{}, err
				}
			}
		} else if len(valueArr) == 1 {
			host := valueArr[0]
			if ip, err := netip.ParseAddr(host); err == nil {
				ips = append(ips, ip)
				isDomain = false
			} else {
				domain = host
			}
		}
	}
	if isDomain {
		return NewHostValueByDomain(domain)
	} else {
		return NewHostValueByIPs(ips)
	}
}

func NewHostValueByIPs(ips []netip.Addr) (HostValue, error) {
	if len(ips) == 0 {
		return HostValue{}, errors.New("ip list is empty")
	}
	return HostValue{
		IsDomain: false,
		IPs:      ips,
	}, nil
}

func NewHostValueByDomain(domain string) (HostValue, error) {
	domain = strings.Trim(domain, ".")
	item := strings.Split(domain, ".")
	if len(item) < 2 {
		return HostValue{}, errors.New("invaild domain")
	}
	return HostValue{
		IsDomain: true,
		Domain:   domain,
	}, nil
}

func (hv HostValue) RandIP() (netip.Addr, error) {
	if hv.IsDomain {
		return netip.Addr{}, errors.New("value type is error")
	}
	return hv.IPs[randv2.IntN(len(hv.IPs))], nil
}
