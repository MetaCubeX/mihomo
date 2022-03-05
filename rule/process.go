package rules

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/process"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var (
	processCache = cache.NewLRUCache(cache.WithAge(2), cache.WithSize(64))

	localIPs = getLocalIPs()
)

type Process struct {
	adapter   string
	process   string
	ruleExtra *C.RuleExtra
}

func (ps *Process) RuleType() C.RuleType {
	return C.Process
}

func (ps *Process) Match(metadata *C.Metadata) bool {
	if metadata.Process != "" {
		return strings.EqualFold(metadata.Process, ps.process)
	}

	// ignore source IP not on local machine
	if !isLocalIP(metadata.SrcIP) {
		return false
	}

	key := fmt.Sprintf("%s:%s:%s", metadata.NetWork.String(), metadata.SrcIP.String(), metadata.SrcPort)
	cached, hit := processCache.Get(key)
	if !hit {
		srcPort, err := strconv.Atoi(metadata.SrcPort)
		if err != nil {
			processCache.Set(key, "")
			return false
		}

		name, err := process.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, srcPort)
		if err != nil {
			log.Debugln("[Rule] find process name %s error: %s", C.Process.String(), err.Error())
		}

		processCache.Set(key, name)

		cached = name
	}

	metadata.Process = cached.(string)

	return strings.EqualFold(metadata.Process, ps.process)
}

func (ps *Process) Adapter() string {
	return ps.adapter
}

func (ps *Process) Payload() string {
	return ps.process
}

func (ps *Process) ShouldResolveIP() bool {
	return false
}

func (ps *Process) RuleExtra() *C.RuleExtra {
	return ps.ruleExtra
}

func NewProcess(process string, adapter string, ruleExtra *C.RuleExtra) (*Process, error) {
	return &Process{
		adapter:   adapter,
		process:   process,
		ruleExtra: ruleExtra,
	}, nil
}

func getLocalIPs() []net.IP {
	ips := []net.IP{net.IPv4(198, 18, 0, 1), net.IPv4zero, net.IPv6zero}

	netInterfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for i := 0; i < len(netInterfaces); i++ {
		if (netInterfaces[i].Flags & net.FlagUp) != 0 {
			adds, _ := netInterfaces[i].Addrs()

			for _, address := range adds {
				if ipNet, ok := address.(*net.IPNet); ok {
					ips = append(ips, ipNet.IP)
				}
			}
		}
	}

	return ips
}

func isLocalIP(srcIP net.IP) bool {
	for _, ip := range localIPs {
		if ip.Equal(srcIP) {
			return true
		}
	}
	return false
}
