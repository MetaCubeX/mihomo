package common

import (
	"bytes"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/patrickmn/go-cache"
	"golang.org/x/net/idna"
)

var lc = cache.New(5*time.Minute, 10*time.Minute)
var arpCommand = "arp"
var arpVar = "-a"

func init() {
	switch os := runtime.GOOS; os {
	case "linux":
		arpCommand = "cat"
		arpVar = "/proc/net/arp"
	case "windows":

	default:

	}
}

type SrcMAC struct {
	*Base
	mac     string
	adapter string
}

func (d *SrcMAC) RuleType() C.RuleType {
	return C.SrcMAC
}

func (d *SrcMAC) Match(metadata *C.Metadata) (bool, string) {
	arpTable, err := getARPTable(false)
	if err != nil {
		log.Errorln("can't initial arp table: %s", err)
		return false, ""
	}

	mac, exists := arpTable[metadata.SrcIP.String()]
	if exists {
		if mac == d.mac {
			return true, d.adapter
		}
	} else {
		arpTable, err := getARPTable(true)
		if err != nil {
			log.Errorln("can't initial arp table: %s", err)
			return false, ""
		}
		mac, exists := arpTable[metadata.SrcIP.String()]
		if exists {
			if mac == d.mac {
				return true, d.adapter
			}
		} else {
			log.Errorln("can't find the IP address in arp table: %s", metadata.SrcIP.String())
		}
	}

	return false, d.adapter
}

func (d *SrcMAC) Adapter() string {
	return d.adapter
}

func (d *SrcMAC) Payload() string {
	return d.mac
}

func NewMAC(mac string, adapter string) *SrcMAC {
	punycode, _ := idna.ToASCII(strings.ToLower(mac))
	return &SrcMAC{
		Base:    &Base{},
		mac:     punycode,
		adapter: adapter,
	}
}

func getARPTable(forceReload bool) (map[string]string, error) {

	item, found := lc.Get("arpTable")
	if found && !forceReload {
		arpTable := item.(map[string]string)
		//log.Infoln("get arpTable from cache")
		return arpTable, nil
	}

	// 执行arp命令
	cmd := exec.Command(arpCommand, arpVar)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	ipRegex := regexp.MustCompile(`(([0-9]{1,3}\.){3}[0-9]{1,3})`)
	macRegex := regexp.MustCompile(`(?i)(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}`)

	// 解析arp命令的输出
	arpTable := make(map[string]string)
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		ip := ipRegex.FindString(line)
		mac := macRegex.FindString(line)

		if len(ip) > 0 && len(mac) > 0 {
			punycode, _ := idna.ToASCII(strings.ToLower(mac))
			arpTable[ip] = punycode
		}
	}
	lc.Set("arpTable", arpTable, cache.DefaultExpiration)
	return arpTable, nil
}

//var _ C.Rule = (*Mac)(nil)
