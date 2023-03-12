package resolver

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"strings"
)

type HostValue struct {
	IsDomain bool
	IPs      []netip.Addr
	Domain   string
}

func NewHostValue(value any) (HostValue, error) {
	isDomain := true
	ips := make([]netip.Addr, 0)
	domain := ""
	switch reflect.TypeOf(value).Kind() {
	case reflect.Slice, reflect.Array:
		isDomain = false
		origin := reflect.ValueOf(value)
		for i := 0; i < origin.Len(); i++ {
			if ip, err := netip.ParseAddr(fmt.Sprintf("%v", origin.Index(i))); err == nil {
				ips = append(ips, ip)
			} else {
				return HostValue{}, err
			}
		}
	case reflect.String:
		host := fmt.Sprintf("%v", value)
		if ip, err := netip.ParseAddr(host); err == nil {
			ips = append(ips, ip)
			isDomain = false
		} else {
			domain = host
		}
	default:
		return HostValue{}, errors.New("value format error, must be string or array")
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
	return hv.IPs[rand.Intn(len(hv.IPs)-1)], nil
}
