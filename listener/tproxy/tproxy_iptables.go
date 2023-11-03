package tproxy

import (
	"errors"
	"fmt"
	"net"
	"runtime"

	"github.com/metacubex/mihomo/common/cmd"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"
)

var (
	dnsPort       uint16
	tProxyPort    uint16
	interfaceName string
)

const (
	PROXY_FWMARK      = "0x2d0"
	PROXY_ROUTE_TABLE = "0x2d0"
)

func SetTProxyIPTables(ifname string, bypass []string, tport uint16, dport uint16) error {
	if _, err := cmd.ExecCmd("iptables -V"); err != nil {
		return fmt.Errorf("current operations system [%s] are not support iptables or command iptables does not exist", runtime.GOOS)
	}

	if ifname == "" {
		return errors.New("the 'interface-name' can not be empty")
	}

	interfaceName = ifname
	tProxyPort = tport
	dnsPort = dport

	// add route
	execCmd(fmt.Sprintf("ip -f inet rule add fwmark %s lookup %s", PROXY_FWMARK, PROXY_ROUTE_TABLE))
	execCmd(fmt.Sprintf("ip -f inet route add local default dev %s table %s", interfaceName, PROXY_ROUTE_TABLE))

	// set FORWARD
	if interfaceName != "lo" {
		execCmd("sysctl -w net.ipv4.ip_forward=1")
		execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -o %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", interfaceName))
		execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -o %s -j ACCEPT", interfaceName))
		execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -i %s ! -o %s -j ACCEPT", interfaceName, interfaceName))
		execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -i %s -o %s -j ACCEPT", interfaceName, interfaceName))
	}

	// set mihomo divert
	execCmd("iptables -t mangle -N mihomo_divert")
	execCmd("iptables -t mangle -F mihomo_divert")
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_divert -j MARK --set-mark %s", PROXY_FWMARK))
	execCmd("iptables -t mangle -A mihomo_divert -j ACCEPT")

	// set pre routing
	execCmd("iptables -t mangle -N mihomo_prerouting")
	execCmd("iptables -t mangle -F mihomo_prerouting")
	execCmd("iptables -t mangle -A mihomo_prerouting -s 172.17.0.0/16 -j RETURN")
	execCmd("iptables -t mangle -A mihomo_prerouting -p udp --dport 53 -j ACCEPT")
	execCmd("iptables -t mangle -A mihomo_prerouting -p tcp --dport 53 -j ACCEPT")
	execCmd("iptables -t mangle -A mihomo_prerouting -m addrtype --dst-type LOCAL -j RETURN")
	addLocalnetworkToChain("mihomo_prerouting", bypass)
	execCmd("iptables -t mangle -A mihomo_prerouting -p tcp -m socket -j mihomo_divert")
	execCmd("iptables -t mangle -A mihomo_prerouting -p udp -m socket -j mihomo_divert")
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_prerouting -p tcp -j TPROXY --on-port %d --tproxy-mark %s/%s", tProxyPort, PROXY_FWMARK, PROXY_FWMARK))
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_prerouting -p udp -j TPROXY --on-port %d --tproxy-mark %s/%s", tProxyPort, PROXY_FWMARK, PROXY_FWMARK))
	execCmd("iptables -t mangle -A PREROUTING -j mihomo_prerouting")

	execCmd(fmt.Sprintf("iptables -t nat -I PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p tcp --dport 53 -j REDIRECT --to %d", dnsPort))
	execCmd(fmt.Sprintf("iptables -t nat -I PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to %d", dnsPort))

	// set post routing
	if interfaceName != "lo" {
		execCmd(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -m addrtype ! --src-type LOCAL -j MASQUERADE", interfaceName))
	}

	// set output
	execCmd("iptables -t mangle -N mihomo_output")
	execCmd("iptables -t mangle -F mihomo_output")
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_output -m mark --mark %#x -j RETURN", dialer.DefaultRoutingMark.Load()))
	execCmd("iptables -t mangle -A mihomo_output -p udp -m multiport --dports 53,123,137 -j ACCEPT")
	execCmd("iptables -t mangle -A mihomo_output -p tcp --dport 53 -j ACCEPT")
	execCmd("iptables -t mangle -A mihomo_output -m addrtype --dst-type LOCAL -j RETURN")
	execCmd("iptables -t mangle -A mihomo_output -m addrtype --dst-type BROADCAST -j RETURN")
	addLocalnetworkToChain("mihomo_output", bypass)
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_output -p tcp -j MARK --set-mark %s", PROXY_FWMARK))
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_output -p udp -j MARK --set-mark %s", PROXY_FWMARK))
	execCmd(fmt.Sprintf("iptables -t mangle -I OUTPUT -o %s -j mihomo_output", interfaceName))

	// set dns output
	execCmd("iptables -t nat -N mihomo_dns_output")
	execCmd("iptables -t nat -F mihomo_dns_output")
	execCmd(fmt.Sprintf("iptables -t nat -A mihomo_dns_output -m mark --mark %#x -j RETURN", dialer.DefaultRoutingMark.Load()))
	execCmd("iptables -t nat -A mihomo_dns_output -s 172.17.0.0/16 -j RETURN")
	execCmd(fmt.Sprintf("iptables -t nat -A mihomo_dns_output -p udp -j REDIRECT --to-ports %d", dnsPort))
	execCmd(fmt.Sprintf("iptables -t nat -A mihomo_dns_output -p tcp -j REDIRECT --to-ports %d", dnsPort))
	execCmd("iptables -t nat -I OUTPUT -p tcp --dport 53 -j mihomo_dns_output")
	execCmd("iptables -t nat -I OUTPUT -p udp --dport 53 -j mihomo_dns_output")

	return nil
}

func CleanupTProxyIPTables() {
	if runtime.GOOS != "linux" || interfaceName == "" || tProxyPort == 0 || dnsPort == 0 {
		return
	}

	log.Warnln("Cleanup tproxy linux iptables")

	if int(dialer.DefaultRoutingMark.Load()) == 2158 {
		dialer.DefaultRoutingMark.Store(0)
	}

	if _, err := cmd.ExecCmd("iptables -t mangle -L mihomo_divert"); err != nil {
		return
	}

	// clean route
	execCmd(fmt.Sprintf("ip -f inet rule del fwmark %s lookup %s", PROXY_FWMARK, PROXY_ROUTE_TABLE))
	execCmd(fmt.Sprintf("ip -f inet route del local default dev %s table %s", interfaceName, PROXY_ROUTE_TABLE))

	// clean FORWARD
	if interfaceName != "lo" {
		execCmd(fmt.Sprintf("iptables -t filter -D FORWARD -i %s ! -o %s -j ACCEPT", interfaceName, interfaceName))
		execCmd(fmt.Sprintf("iptables -t filter -D FORWARD -i %s -o %s -j ACCEPT", interfaceName, interfaceName))
		execCmd(fmt.Sprintf("iptables -t filter -D FORWARD -o %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", interfaceName))
		execCmd(fmt.Sprintf("iptables -t filter -D FORWARD -o %s -j ACCEPT", interfaceName))
	}

	// clean PREROUTING
	execCmd(fmt.Sprintf("iptables -t nat -D PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p tcp --dport 53 -j REDIRECT --to %d", dnsPort))
	execCmd(fmt.Sprintf("iptables -t nat -D PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to %d", dnsPort))
	execCmd("iptables -t mangle -D PREROUTING -j mihomo_prerouting")

	// clean POSTROUTING
	if interfaceName != "lo" {
		execCmd(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -m addrtype ! --src-type LOCAL -j MASQUERADE", interfaceName))
	}

	// clean OUTPUT
	execCmd(fmt.Sprintf("iptables -t mangle -D OUTPUT -o %s -j mihomo_output", interfaceName))
	execCmd("iptables -t nat -D OUTPUT -p tcp --dport 53 -j mihomo_dns_output")
	execCmd("iptables -t nat -D OUTPUT -p udp --dport 53 -j mihomo_dns_output")

	// clean chain
	execCmd("iptables -t mangle -F mihomo_prerouting")
	execCmd("iptables -t mangle -X mihomo_prerouting")
	execCmd("iptables -t mangle -F mihomo_divert")
	execCmd("iptables -t mangle -X mihomo_divert")
	execCmd("iptables -t mangle -F mihomo_output")
	execCmd("iptables -t mangle -X mihomo_output")
	execCmd("iptables -t nat -F mihomo_dns_output")
	execCmd("iptables -t nat -X mihomo_dns_output")

	interfaceName = ""
	tProxyPort = 0
	dnsPort = 0
}

func addLocalnetworkToChain(chain string, bypass []string) {
	for _, bp := range bypass {
		_, _, err := net.ParseCIDR(bp)
		if err != nil {
			log.Warnln("[IPTABLES] %s", err)
			continue
		}
		execCmd(fmt.Sprintf("iptables -t mangle -A %s -d %s -j RETURN", chain, bp))
	}
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 0.0.0.0/8 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 10.0.0.0/8 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 100.64.0.0/10 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 127.0.0.0/8 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 169.254.0.0/16 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 172.16.0.0/12 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 192.0.0.0/24 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 192.0.2.0/24 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 192.88.99.0/24 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 192.168.0.0/16 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 198.51.100.0/24 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 203.0.113.0/24 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 224.0.0.0/4 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 240.0.0.0/4 -j RETURN", chain))
	execCmd(fmt.Sprintf("iptables -t mangle -A %s -d 255.255.255.255/32 -j RETURN", chain))
}

func execCmd(cmdStr string) {
	log.Debugln("[IPTABLES] %s", cmdStr)

	_, err := cmd.ExecCmd(cmdStr)
	if err != nil {
		log.Warnln("[IPTABLES] exec cmd: %v", err)
	}
}
