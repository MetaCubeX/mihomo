package correctnet

import (
	"net"
	"net/http"
	"strings"
)

func extractIPFamily(ip net.IP) (family string) {
	if len(ip) == 0 {
		// real family independent wildcard address, such as ":443"
		return ""
	}
	if p4 := ip.To4(); len(p4) == net.IPv4len {
		return "4"
	}
	return "6"
}

func tcpAddrNetwork(addr *net.TCPAddr) (network string) {
	if addr == nil {
		return "tcp"
	}
	return "tcp" + extractIPFamily(addr.IP)
}

func udpAddrNetwork(addr *net.UDPAddr) (network string) {
	if addr == nil {
		return "udp"
	}
	return "udp" + extractIPFamily(addr.IP)
}

func ipAddrNetwork(addr *net.IPAddr) (network string) {
	if addr == nil {
		return "ip"
	}
	return "ip" + extractIPFamily(addr.IP)
}

func Listen(network, address string) (net.Listener, error) {
	if network == "tcp" {
		tcpAddr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, err
		}
		return ListenTCP(network, tcpAddr)
	}
	return net.Listen(network, address)
}

func ListenTCP(network string, laddr *net.TCPAddr) (*net.TCPListener, error) {
	if network == "tcp" {
		return net.ListenTCP(tcpAddrNetwork(laddr), laddr)
	}
	return net.ListenTCP(network, laddr)
}

func ListenPacket(network, address string) (listener net.PacketConn, err error) {
	if network == "udp" {
		udpAddr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}
		return ListenUDP(network, udpAddr)
	}
	if strings.HasPrefix(network, "ip:") {
		proto := network[3:]
		ipAddr, err := net.ResolveIPAddr(proto, address)
		if err != nil {
			return nil, err
		}
		return net.ListenIP(ipAddrNetwork(ipAddr)+":"+proto, ipAddr)
	}
	return net.ListenPacket(network, address)
}

func ListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	if network == "udp" {
		return net.ListenUDP(udpAddrNetwork(laddr), laddr)
	}
	return net.ListenUDP(network, laddr)
}

func HTTPListenAndServe(address string, handler http.Handler) error {
	listener, err := Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	return http.Serve(listener, handler)
}
