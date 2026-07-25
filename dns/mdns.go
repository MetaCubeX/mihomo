package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	D "github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	mdnsPort            = 5353
	mdnsDefaultTimeout  = time.Second
	mdnsResponseSettle  = 100 * time.Millisecond
	mdnsMulticastTTL    = 255
	mdnsCacheFlush      = uint16(1 << 15)
	mdnsClassMask       = ^mdnsCacheFlush
	mdnsMaxDatagramSize = 65535
)

var (
	errMDNSClientClosed = errors.New("mDNS client is closed")
	errMDNSTimeout      = errors.New("mDNS query timed out")
)

type mdnsInterface struct {
	iface net.Interface
	ipv4  net.IP
	ipv6  net.IP
}

type mdnsTarget struct {
	network   string
	iface     *net.Interface
	localAddr *net.UDPAddr
	addr      *net.UDPAddr
}

type mdnsEvent struct {
	msg    *D.Msg
	err    error
	packet bool
	done   bool
}

type mdnsClient struct {
	timeout  time.Duration
	settle   time.Duration
	platform func(context.Context, *D.Msg) (*D.Msg, bool, error)
	targets  func() ([]mdnsTarget, error)
	socketMu sync.Mutex
	sockets  map[net.Conn]struct{}
	closed   bool
}

var _ dnsClient = (*mdnsClient)(nil)

func newMDNSClient() *mdnsClient {
	client := &mdnsClient{
		timeout: mdnsDefaultTimeout,
		settle:  mdnsResponseSettle,
		targets: discoverMDNSTargets,
		sockets: map[net.Conn]struct{}{},
	}
	client.platform = client.exchangeMDNSPlatform
	return client
}

func (c *mdnsClient) Address() string {
	return "mdns://"
}

func (c *mdnsClient) ExchangeContext(ctx context.Context, request *D.Msg) (*D.Msg, error) {
	if len(request.Question) == 0 {
		return nil, errors.New("mDNS query should have one question at least")
	}
	if c.isClosed() {
		return nil, errMDNSClientClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.platform != nil {
		if response, handled, err := c.platform(ctx, request); handled {
			return response, err
		}
	}

	targets, err := c.targets()
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("no multicast-capable network interface")
	}

	query := request.Copy()
	query.Id = 0
	query.Response = false
	query.RecursionDesired = false
	wire, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack mDNS query: %w", err)
	}

	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	events := make(chan mdnsEvent, len(targets)*2)
	connections := make([]*net.UDPConn, 0, len(targets))
	var readers sync.WaitGroup
	defer func() {
		cancel()
		for _, conn := range connections {
			_ = conn.Close()
		}
		readers.Wait()
		for _, conn := range connections {
			c.unregisterSocket(conn)
		}
	}()

	var setupErrors []error
	for _, target := range targets {
		conn, err := openMDNSSocket(target)
		if err != nil {
			setupErrors = append(setupErrors, err)
			continue
		}
		if !c.registerSocket(conn) {
			_ = conn.Close()
			return nil, errMDNSClientClosed
		}

		if deadline, ok := queryCtx.Deadline(); ok {
			_ = conn.SetReadDeadline(deadline)
		}
		if _, err = conn.WriteToUDP(wire, target.addr); err != nil {
			c.unregisterSocket(conn)
			_ = conn.Close()
			setupErrors = append(setupErrors, fmt.Errorf("send mDNS query on %s: %w", target, err))
			continue
		}

		connections = append(connections, conn)
		readers.Add(1)
		go func() {
			defer readers.Done()
			readMDNSResponses(queryCtx, conn, query, events)
		}()
	}

	if len(connections) == 0 {
		if len(setupErrors) == 0 {
			return nil, errors.New("unable to open an mDNS socket")
		}
		return nil, fmt.Errorf("unable to open an mDNS socket: %w", errors.Join(setupErrors...))
	}

	var (
		responses     []*D.Msg
		firstError    error
		activeReaders = len(connections)
		packetCount   int
		settleC       <-chan time.Time
		settleTimer   *time.Timer
	)
	defer func() {
		if settleTimer != nil {
			settleTimer.Stop()
		}
	}()

	for {
		select {
		case event := <-events:
			if event.done {
				activeReaders--
				if activeReaders == 0 {
					if len(responses) > 0 {
						return mergeMDNSResponses(request, responses), nil
					}
					if c.isClosed() {
						return nil, errMDNSClientClosed
					}
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					if firstError != nil {
						var netError net.Error
						if errors.As(firstError, &netError) && netError.Timeout() {
							return nil, fmt.Errorf("%w after receiving %d packets: %w", errMDNSTimeout, packetCount, firstError)
						}
						return nil, fmt.Errorf("all mDNS sockets closed: %w", firstError)
					}
					return nil, errors.New("all mDNS sockets closed without a response")
				}
				continue
			}
			if event.err != nil {
				if firstError == nil {
					firstError = event.err
				}
				continue
			}
			if event.packet {
				packetCount++
			}
			if event.msg == nil {
				continue
			}
			responses = append(responses, event.msg)
			if settleTimer == nil {
				settleTimer = time.NewTimer(c.settle)
			} else {
				if !settleTimer.Stop() {
					select {
					case <-settleTimer.C:
					default:
					}
				}
				settleTimer.Reset(c.settle)
			}
			settleC = settleTimer.C
		case <-settleC:
			return mergeMDNSResponses(request, responses), nil
		case <-queryCtx.Done():
			if len(responses) > 0 {
				return mergeMDNSResponses(request, responses), nil
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if firstError != nil && !errors.Is(firstError, net.ErrClosed) {
				return nil, fmt.Errorf("%w after receiving %d packets: %w", errMDNSTimeout, packetCount, firstError)
			}
			return nil, fmt.Errorf("%w after receiving %d packets: %w", errMDNSTimeout, packetCount, queryCtx.Err())
		}
	}
}

func (c *mdnsClient) ResetConnection() {
	c.closeSockets(false)
}

func (c *mdnsClient) Close() error {
	c.closeSockets(true)
	return nil
}

func (c *mdnsClient) closeSockets(closeClient bool) {
	c.socketMu.Lock()
	if closeClient {
		c.closed = true
	}
	sockets := make([]net.Conn, 0, len(c.sockets))
	for conn := range c.sockets {
		sockets = append(sockets, conn)
	}
	c.socketMu.Unlock()

	for _, conn := range sockets {
		_ = conn.Close()
	}
}

func (c *mdnsClient) registerSocket(conn net.Conn) bool {
	c.socketMu.Lock()
	defer c.socketMu.Unlock()
	if c.closed {
		return false
	}
	c.sockets[conn] = struct{}{}
	return true
}

func (c *mdnsClient) unregisterSocket(conn net.Conn) {
	c.socketMu.Lock()
	delete(c.sockets, conn)
	c.socketMu.Unlock()
}

func (c *mdnsClient) activeSockets() int {
	c.socketMu.Lock()
	defer c.socketMu.Unlock()
	return len(c.sockets)
}

func (c *mdnsClient) isClosed() bool {
	c.socketMu.Lock()
	defer c.socketMu.Unlock()
	return c.closed
}

func discoverMDNSTargets() ([]mdnsTarget, error) {
	interfaces, err := discoverMDNSInterfaces()
	if err != nil {
		return nil, err
	}
	return targetsForMDNSInterfaces(interfaces), nil
}

func discoverMDNSInterfaces() ([]mdnsInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces for mDNS: %w", err)
	}

	result := make([]mdnsInterface, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagMulticast == 0 ||
			iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		item := mdnsInterface{iface: iface}
		for _, rawAddr := range addrs {
			ip, _, err := net.ParseCIDR(rawAddr.String())
			if err != nil {
				if ipAddr, ok := rawAddr.(*net.IPAddr); ok {
					ip = ipAddr.IP
				} else {
					continue
				}
			}
			if ip.To4() != nil {
				if item.ipv4 == nil {
					item.ipv4 = ip.To4()
				}
			} else if ip.To16() != nil {
				if item.ipv6 == nil || ip.IsLinkLocalUnicast() {
					item.ipv6 = ip.To16()
				}
			}
		}
		if item.ipv4 != nil || item.ipv6 != nil {
			result = append(result, item)
		}
	}
	return result, nil
}

func targetsForMDNSInterfaces(interfaces []mdnsInterface) []mdnsTarget {
	targets := make([]mdnsTarget, 0, len(interfaces)*2)
	for i := range interfaces {
		item := &interfaces[i]
		if item.iface.Flags&net.FlagUp == 0 ||
			item.iface.Flags&net.FlagMulticast == 0 ||
			item.iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		if item.ipv4 != nil {
			targets = append(targets, mdnsTarget{
				network:   "udp4",
				iface:     &item.iface,
				localAddr: &net.UDPAddr{IP: item.ipv4},
				addr:      &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort},
			})
		}
		if item.ipv6 != nil {
			targets = append(targets, mdnsTarget{
				network:   "udp6",
				iface:     &item.iface,
				localAddr: &net.UDPAddr{IP: item.ipv6, Zone: item.iface.Name},
				addr:      &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: mdnsPort, Zone: item.iface.Name},
			})
		}
	}
	return targets
}

func openMDNSSocket(target mdnsTarget) (*net.UDPConn, error) {
	var (
		conn *net.UDPConn
		err  error
	)
	if target.iface != nil && target.addr.IP.IsMulticast() {
		conn, err = net.ListenMulticastUDP(target.network, target.iface, target.addr)
	} else {
		localAddr := target.localAddr
		if localAddr == nil {
			localAddr = &net.UDPAddr{}
		}
		switch target.network {
		case "udp4":
			if localAddr.IP == nil {
				localAddr.IP = net.IPv4zero
			}
		case "udp6":
			if localAddr.IP == nil {
				localAddr.IP = net.IPv6unspecified
			}
		default:
			return nil, fmt.Errorf("unsupported mDNS network %q", target.network)
		}
		conn, err = net.ListenUDP(target.network, localAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("listen for mDNS on %s: %w", target, err)
	}
	if target.iface == nil {
		return conn, nil
	}

	switch target.network {
	case "udp4":
		packetConn := ipv4.NewPacketConn(conn)
		if err = packetConn.SetMulticastInterface(target.iface); err == nil {
			err = packetConn.SetMulticastTTL(mdnsMulticastTTL)
		}
		if err == nil {
			err = packetConn.SetMulticastLoopback(true)
		}
	case "udp6":
		packetConn := ipv6.NewPacketConn(conn)
		if err = packetConn.SetMulticastInterface(target.iface); err == nil {
			err = packetConn.SetMulticastHopLimit(mdnsMulticastTTL)
		}
		if err == nil {
			err = packetConn.SetMulticastLoopback(true)
		}
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("configure mDNS socket on %s: %w", target, err)
	}
	return conn, nil
}

func readMDNSResponses(ctx context.Context, conn *net.UDPConn, query *D.Msg, events chan<- mdnsEvent) {
	defer func() {
		select {
		case events <- mdnsEvent{done: true}:
		case <-ctx.Done():
		}
	}()
	buffer := make([]byte, mdnsMaxDatagramSize)
	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() == nil {
				select {
				case events <- mdnsEvent{err: err}:
				case <-ctx.Done():
				}
			}
			return
		}

		response := &D.Msg{}
		if err = response.Unpack(buffer[:n]); err != nil {
			continue
		}
		event := mdnsEvent{packet: true}
		if isMDNSResponseForQuery(response, query) {
			event.msg = response
		}
		select {
		case events <- event:
		case <-ctx.Done():
			return
		}
	}
}

func isMDNSResponseForQuery(response, query *D.Msg) bool {
	if !response.Response || response.Rcode != D.RcodeSuccess {
		return false
	}
	if response.Id != 0 && response.Id != query.Id {
		return false
	}

	wanted := query.Question[0]
	for _, question := range response.Question {
		if strings.EqualFold(question.Name, wanted.Name) &&
			question.Qtype == wanted.Qtype &&
			question.Qclass&mdnsClassMask == wanted.Qclass&mdnsClassMask {
			return true
		}
	}
	for _, record := range append(response.Answer, response.Extra...) {
		header := record.Header()
		if !strings.EqualFold(header.Name, wanted.Name) ||
			header.Class&mdnsClassMask != wanted.Qclass&mdnsClassMask {
			continue
		}
		if header.Rrtype == wanted.Qtype || header.Rrtype == D.TypeCNAME || wanted.Qtype == D.TypeANY {
			return true
		}
	}
	return false
}

func mergeMDNSResponses(request *D.Msg, responses []*D.Msg) *D.Msg {
	response := &D.Msg{}
	response.SetReply(request)
	response.Authoritative = true
	response.RecursionAvailable = false

	question := request.Question[0]
	names := map[string]struct{}{canonicalMDNSName(question.Name): {}}
	records := make([]D.RR, 0)
	for _, message := range responses {
		records = append(records, message.Answer...)
		records = append(records, message.Extra...)
	}

	for {
		changed := false
		for _, record := range records {
			cname, ok := record.(*D.CNAME)
			if !ok {
				continue
			}
			if _, ok = names[canonicalMDNSName(cname.Hdr.Name)]; !ok {
				continue
			}
			target := canonicalMDNSName(cname.Target)
			if _, ok = names[target]; !ok {
				names[target] = struct{}{}
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	seen := map[string]int{}
	for _, record := range records {
		header := record.Header()
		if header.Class&mdnsClassMask != D.ClassINET {
			continue
		}
		if _, ok := names[canonicalMDNSName(header.Name)]; !ok {
			continue
		}
		if header.Rrtype != question.Qtype && header.Rrtype != D.TypeCNAME && question.Qtype != D.TypeANY {
			continue
		}

		record = D.Copy(record)
		record.Header().Class &= mdnsClassMask
		keyRecord := D.Copy(record)
		keyRecord.Header().Ttl = 0
		key := strings.ToLower(keyRecord.String())
		if index, ok := seen[key]; ok {
			if response.Answer[index].Header().Ttl < record.Header().Ttl {
				response.Answer[index].Header().Ttl = record.Header().Ttl
			}
			continue
		}
		seen[key] = len(response.Answer)
		response.Answer = append(response.Answer, record)
	}
	return response
}

func canonicalMDNSName(name string) string {
	return strings.ToLower(D.Fqdn(name))
}

func (t mdnsTarget) String() string {
	if t.iface == nil {
		return fmt.Sprintf("%s/%s", t.network, t.addr)
	}
	return fmt.Sprintf("%s/%s/%s", t.network, t.iface.Name, t.addr)
}
