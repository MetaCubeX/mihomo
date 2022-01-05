package tproxy

import (
	"errors"
	"fmt"
	"os/exec"
	U "os/user"
	"runtime"
	"strings"

	"github.com/Dreamacro/clash/log"
)

var (
	interfaceName = ""
	tproxyPort    = 0
	dnsPort       = 0
)

const (
	PROXY_FWMARK      = "0x2d0"
	PROXY_ROUTE_TABLE = "0x2d0"
	USERNAME          = "Clash.Meta"
)

func SetTProxyLinuxIPTables(ifname string, tport int, dport int) error {
	var err error
	if _, err = execCmd("iptables -V"); err != nil {
		return fmt.Errorf("current operations system [%s] are not support iptables or command iptables does not exist", runtime.GOOS)
	}

	user, err := U.Lookup(USERNAME)
	if err != nil {
		return fmt.Errorf("the user \" %s\" does not exist, please create it", USERNAME)
	}

	if ifname == "" {
		return errors.New("the 'interface-name' can not be empty")
	}

	ownerUid := user.Uid

	interfaceName = ifname
	tproxyPort = tport
	dnsPort = dport

	// add route
	execCmd(fmt.Sprintf("ip -f inet rule add fwmark %s lookup %s", PROXY_FWMARK, PROXY_ROUTE_TABLE))
	execCmd(fmt.Sprintf("ip -f inet route add local default dev %s table %s", interfaceName, PROXY_ROUTE_TABLE))

	// set FORWARD
	execCmd("sysctl -w net.ipv4.ip_forward=1")
	execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -o %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", interfaceName))
	execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -o %s -j ACCEPT", interfaceName))
	execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -i %s ! -o %s -j ACCEPT", interfaceName, interfaceName))
	execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -i %s -o %s -j ACCEPT", interfaceName, interfaceName))

	// set clash divert
	execCmd("iptables -t mangle -N clash_divert")
	execCmd("iptables -t mangle -F clash_divert")
	execCmd(fmt.Sprintf("iptables -t mangle -A clash_divert -j MARK --set-mark %s", PROXY_FWMARK))
	execCmd("iptables -t mangle -A clash_divert -j ACCEPT")

	// set pre routing
	execCmd("iptables -t mangle -N clash_prerouting")
	execCmd("iptables -t mangle -F clash_prerouting")
	execCmd("iptables -t mangle -A clash_prerouting -s 172.17.0.0/16 -j RETURN")
	execCmd("iptables -t mangle -A clash_prerouting -p udp --dport 53 -j ACCEPT")
	execCmd("iptables -t mangle -A clash_prerouting -p tcp --dport 53 -j ACCEPT")
	execCmd("iptables -t mangle -A clash_prerouting -m addrtype --dst-type LOCAL -j RETURN")
	addLocalnetworkToChain("clash_prerouting")
	execCmd("iptables -t mangle -A clash_prerouting -p tcp -m socket -j clash_divert")
	execCmd("iptables -t mangle -A clash_prerouting -p udp -m socket -j clash_divert")
	execCmd(fmt.Sprintf("iptables -t mangle -A clash_prerouting -p tcp -j TPROXY --on-port %d --tproxy-mark %s/%s", tproxyPort, PROXY_FWMARK, PROXY_FWMARK))
	execCmd(fmt.Sprintf("iptables -t mangle -A clash_prerouting -p udp -j TPROXY --on-port %d --tproxy-mark %s/%s", tproxyPort, PROXY_FWMARK, PROXY_FWMARK))
	execCmd("iptables -t mangle -A PREROUTING -j clash_prerouting")

	execCmd(fmt.Sprintf("iptables -t nat -I PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p tcp --dport 53 -j REDIRECT --to %d", dnsPort))
	execCmd(fmt.Sprintf("iptables -t nat -I PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to %d", dnsPort))

	// set post routing
	execCmd(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -m addrtype ! --src-type LOCAL -j MASQUERADE", interfaceName))

	// set output
	execCmd("iptables -t mangle -N clash_output")
	execCmd("iptables -t mangle -F clash_output")
	execCmd(fmt.Sprintf("iptables -t mangle -A clash_output -m owner --uid-owner %s -j RETURN", ownerUid))
	execCmd("iptables -t mangle -A clash_output -p udp -m multiport --dports 53,123,137 -j ACCEPT")
	execCmd("iptables -t mangle -A clash_output -p tcp --dport 53 -j ACCEPT")
	execCmd("iptables -t mangle -A clash_output -m addrtype --dst-type LOCAL -j RETURN")
	execCmd("iptables -t mangle -A clash_output -m addrtype --dst-type BROADCAST -j RETURN")
	addLocalnetworkToChain("clash_output")
	execCmd(fmt.Sprintf("iptables -t mangle -A clash_output -p tcp -j MARK --set-mark %s", PROXY_FWMARK))
	execCmd(fmt.Sprintf("iptables -t mangle -A clash_output -p udp -j MARK --set-mark %s", PROXY_FWMARK))
	execCmd(fmt.Sprintf("iptables -t mangle -I OUTPUT -o %s -j clash_output", interfaceName))

	// set dns output
	execCmd("iptables -t nat -N clash_dns_output")
	execCmd("iptables -t nat -F clash_dns_output")
	execCmd(fmt.Sprintf("iptables -t nat -A clash_dns_output -m owner --uid-owner %s -j RETURN", ownerUid))
	execCmd("iptables -t nat -A clash_dns_output -s 172.17.0.0/16 -j RETURN")
	execCmd(fmt.Sprintf("iptables -t nat -A clash_dns_output -p udp -j REDIRECT --to-ports %d", dnsPort))
	execCmd(fmt.Sprintf("iptables -t nat -A clash_dns_output -p tcp -j REDIRECT --to-ports %d", dnsPort))
	execCmd("iptables -t nat -I OUTPUT -p tcp --dport 53 -j clash_dns_output")
	execCmd("iptables -t nat -I OUTPUT -p udp --dport 53 -j clash_dns_output")

	log.Infoln("[TProxy] Setting iptables completed")
	return nil
}

func CleanUpTProxyLinuxIPTables() {
	if interfaceName == "" || tproxyPort == 0 || dnsPort == 0 {
		return
	}

	log.Warnln("Clean up tproxy linux iptables")

	if _, err := execCmd("iptables -t mangle -L clash_divert"); err != nil {
		return
	}

	// clean route
	execCmd(fmt.Sprintf("ip -f inet rule del fwmark %s lookup %s", PROXY_FWMARK, PROXY_ROUTE_TABLE))
	execCmd(fmt.Sprintf("ip -f inet route del local default dev %s table %s", interfaceName, PROXY_ROUTE_TABLE))

	// clean FORWARD
	execCmd(fmt.Sprintf("iptables -t filter -D FORWARD -i %s ! -o %s -j ACCEPT", interfaceName, interfaceName))
	execCmd(fmt.Sprintf("iptables -t filter -D FORWARD -i %s -o %s -j ACCEPT", interfaceName, interfaceName))
	execCmd(fmt.Sprintf("iptables -t filter -D FORWARD -o %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", interfaceName))
	execCmd(fmt.Sprintf("iptables -t filter -D FORWARD -o %s -j ACCEPT", interfaceName))

	// clean PREROUTING
	execCmd(fmt.Sprintf("iptables -t nat -D PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p tcp --dport 53 -j REDIRECT --to %d", dnsPort))
	execCmd(fmt.Sprintf("iptables -t nat -D PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to %d", dnsPort))
	execCmd("iptables -t mangle -D PREROUTING -j clash_prerouting")

	// clean POSTROUTING
	execCmd(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -m addrtype ! --src-type LOCAL -j MASQUERADE", interfaceName))

	// clean OUTPUT
	execCmd(fmt.Sprintf("iptables -t mangle -D OUTPUT -o %s -j clash_output", interfaceName))
	execCmd("iptables -t nat -D OUTPUT -p tcp --dport 53 -j clash_dns_output")
	execCmd("iptables -t nat -D OUTPUT -p udp --dport 53 -j clash_dns_output")

	// clean chain
	execCmd("iptables -t mangle -F clash_prerouting")
	execCmd("iptables -t mangle -X clash_prerouting")
	execCmd("iptables -t mangle -F clash_divert")
	execCmd("iptables -t mangle -X clash_divert")
	execCmd("iptables -t mangle -F clash_output")
	execCmd("iptables -t mangle -X clash_output")
	execCmd("iptables -t nat -F clash_dns_output")
	execCmd("iptables -t nat -X clash_dns_output")
}

func addLocalnetworkToChain(chain string) {
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

func execCmd(cmdstr string) (string, error) {
	log.Debugln("[TProxy] %s", cmdstr)

	args := strings.Split(cmdstr, " ")
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorln("[TProxy] error: %s, %s", err.Error(), string(out))
		return "", err
	}

	return string(out), nil
}
