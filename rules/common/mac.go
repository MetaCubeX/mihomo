package common

import (
	"errors"
	"github.com/metacubex/mihomo/common/cmd"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var arpTable = make(map[string]string)

const reloadInterval = 5 * time.Minute

var startOnce sync.Once
func init() {
}

type SrcMAC struct {
	*Base
	mac     string
	adapter string
}

func (d *SrcMAC) RuleType() C.RuleType {
	return C.SrcMAC
}

func getLoadArpTableFunc() func() (string, error) {
	const ipv6Error = "can't load ipv6 arp table, SRC-MAC rule can't match src ipv6 address"

	getIpv4Only := func() (string, error) {
		return cmd.ExecCmd("arp -a")
	}

	switch runtime.GOOS {
	case "linux":
		result, err := cmd.ExecCmd("ip --help")
		if err != nil {
			result += err.Error()
		}
		if strings.Contains(result, "neigh") && strings.Contains(result, "inet6") {
			return func() (string, error) {
				return cmd.ExecCmd("ip -s neigh show")
			}
		} else {
			log.Warnln(ipv6Error)
			const arpPath = "/proc/net/arp"
			if file, err := os.Open(arpPath); err == nil {
				defer file.Close()
				return func() (string, error) {
					data, err := os.ReadFile(arpPath)
					if err != nil {
						return "", err
					}
					return string(data), nil
				}
			} else {
				return func() (string, error) {
					return cmd.ExecCmd("arp -a -n")
				}
			}
		}

	case "windows":
		getIpv6ArpWindows := func() (string, error) {
			return cmd.ExecCmd("netsh interface ipv6 show neighbors")
		}
		result, err := getIpv6ArpWindows()
		if err != nil || !strings.Contains(result, "----") {
			log.Warnln(ipv6Error)
			return getIpv4Only
		}
		return func() (string, error) {
			result, err := cmd.ExecCmd("netsh interface ipv4 show neighbors")
			if err != nil {
				return "", err
			}
			ipv6Result, err := getIpv6ArpWindows()
			if err == nil {
				result += ipv6Result
			}
			return result, nil
		}

	default:
		log.Warnln(ipv6Error)
		return getIpv4Only
	}
}

func (d *SrcMAC) Match(metadata *C.Metadata) (bool, string) {
	table := getArpTable()
	srcIP := metadata.SrcIP.String()
	mac, exists := table[srcIP]
	if exists {
		if mac == d.mac {
			return true, d.adapter
		}
	} else {
		log.Warnln("can't find the IP address in arp table: %s", srcIP)
	}
	return false, d.adapter
}

func (d *SrcMAC) Adapter() string {
	return d.adapter
}

func (d *SrcMAC) Payload() string {
	return d.mac
}

var macRegex = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)

func NewMAC(mac string, adapter string) (*SrcMAC, error) {
	macAddr := strings.ReplaceAll(strings.ToLower(mac), "-", ":")
	if !macRegex.MatchString(macAddr) {
		return nil, errors.New("mac address format error: " + mac)
	}
	return &SrcMAC{
		Base:    &Base{},
		mac:     macAddr,
		adapter: adapter,
	}, nil
}

var arpMapRegex = regexp.MustCompile(`((([0-9]{1,3}\.){3}[0-9]{1,3})|(\b[0-9a-fA-F:].*?:.*?))\s.*?\b(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\b`)

func getArpTable() map[string]string {
	startOnce.Do(func() {
		loadArpTable := getLoadArpTableFunc()
		table, err := reloadArpTable(loadArpTable)
		if err == nil {
			arpTable = table
		} else {
			log.Errorln("init arp table failed: %s", err)
		}
		timer := time.NewTimer(reloadInterval)
		go func() {
			for {
				<-timer.C
				table, err := reloadArpTable(loadArpTable)
				if err == nil {
					arpTable = table
				} else {
					log.Errorln("reload arp table failed: %s", err)
				}
				timer.Reset(reloadInterval)
			}
		}()
	})
	return arpTable
}

func reloadArpTable(loadArpFunc func() (string, error)) (map[string]string, error) {
	result, err := loadArpFunc()
	if err != nil {
		return nil, err
	}
	newArpTable := make(map[string]string)
	for _, line := range strings.Split(result, "\n") {
		matches := arpMapRegex.FindStringSubmatch(line)
		if matches == nil || len(matches) <= 0 {
			continue
		}
		ip := matches[1]
		mac := strings.ToLower(matches[5])
		if strings.Contains(mac, "-") {
			mac = strings.ReplaceAll(mac, "-", ":")
		}
		newArpTable[ip] = mac
	}
	return newArpTable, nil
}
