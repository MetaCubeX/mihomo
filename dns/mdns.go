package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

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
	mdnsMaxResponses    = 256
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
	response *mdnsResponse
	err      error
	packet   bool
	done     bool
}

type mdnsResponse struct {
	msg *D.Msg
	// ifIndex identifies the ingress interface. Records from different
	// interfaces are never linked into one CNAME chain.
	ifIndex     int
	source      *net.UDPAddr
	destination net.IP
	// hopLimit is retained for diagnostics and policy decisions. RFC 6762
	// recommends 255, but does not require receivers to reject other values.
	hopLimit int
}

type mdnsClient struct {
	timeout             time.Duration
	settle              time.Duration
	platform            func(context.Context, *D.Msg) (*D.Msg, bool, error)
	targets             func() ([]mdnsTarget, error)
	platformFallbackLog sync.Once
	socketMu            sync.Mutex
	sockets             map[net.Conn]struct{}
	closed              bool
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

func (c *mdnsClient) ExchangeContext(ctx context.Context, request *D.Msg) (response *D.Msg, err error) {
	if len(request.Question) == 0 {
		return nil, errors.New("mDNS query should have one question at least")
	}
	if c.isClosed() {
		return nil, errMDNSClientClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var platformErr error
	if c.platform != nil {
		if response, handled, err := c.platform(queryCtx, request); handled {
			return response, err
		} else if err != nil {
			platformErr = err
			c.platformFallbackLog.Do(func() {
				log.Warnln("[DNS] %v; falling back to portable multicast", err)
			})
		}
	}
	defer func() {
		if err != nil && platformErr != nil {
			err = fmt.Errorf("mDNS platform resolver and multicast fallback failed: %w", errors.Join(platformErr, err))
		}
	}()

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
		target := target
		readers.Add(1)
		go func() {
			defer readers.Done()
			readMDNSResponses(queryCtx, conn, target, events)
		}()
	}

	if len(connections) == 0 {
		if len(setupErrors) == 0 {
			return nil, errors.New("unable to open an mDNS socket")
		}
		return nil, fmt.Errorf("unable to open an mDNS socket: %w", errors.Join(setupErrors...))
	}

	var (
		responses     []mdnsResponse
		merged        *D.Msg
		mergedKey     string
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
					if merged != nil {
						return merged, nil
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
			if event.response == nil {
				continue
			}
			if len(responses) == mdnsMaxResponses {
				copy(responses, responses[1:])
				responses[len(responses)-1] = *event.response
			} else {
				responses = append(responses, *event.response)
			}
			candidate, available := mergeMDNSResponses(request, responses)
			if !available {
				continue
			}
			candidateKey := candidate.String()
			merged = candidate
			if candidateKey == mergedKey {
				continue
			}
			mergedKey = candidateKey
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
			return merged, nil
		case <-queryCtx.Done():
			if merged != nil {
				return merged, nil
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
		if err = packetConn.SetControlMessage(ipv4.FlagTTL|ipv4.FlagDst|ipv4.FlagInterface, true); err == nil {
			err = packetConn.SetMulticastInterface(target.iface)
		}
		if err == nil {
			err = packetConn.SetMulticastTTL(mdnsMulticastTTL)
		}
		if err == nil {
			err = packetConn.SetMulticastLoopback(true)
		}
	case "udp6":
		packetConn := ipv6.NewPacketConn(conn)
		if err = packetConn.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagDst|ipv6.FlagInterface, true); err == nil {
			err = packetConn.SetMulticastInterface(target.iface)
		}
		if err == nil {
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

func readMDNSResponses(ctx context.Context, conn *net.UDPConn, target mdnsTarget, events chan<- mdnsEvent) {
	defer func() {
		select {
		case events <- mdnsEvent{done: true}:
		case <-ctx.Done():
		}
	}()

	readPacket := mdnsPacketReader(conn, target)
	buffer := make([]byte, mdnsMaxDatagramSize)
	for {
		n, response, err := readPacket(buffer)
		if err != nil {
			if ctx.Err() == nil {
				select {
				case events <- mdnsEvent{err: err}:
				case <-ctx.Done():
				}
			}
			return
		}
		event := mdnsEvent{packet: true}
		if !validMDNSTransport(response, target) {
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
			continue
		}

		response.msg = &D.Msg{}
		if err = response.msg.Unpack(buffer[:n]); err != nil || !validMDNSMessage(response.msg) {
			continue
		}
		event.response = response
		select {
		case events <- event:
		case <-ctx.Done():
			return
		}
	}
}

func mdnsPacketReader(conn *net.UDPConn, target mdnsTarget) func([]byte) (int, *mdnsResponse, error) {
	if target.iface == nil || !target.addr.IP.IsMulticast() {
		return func(buffer []byte) (int, *mdnsResponse, error) {
			n, source, err := conn.ReadFromUDP(buffer)
			return n, &mdnsResponse{source: source}, err
		}
	}

	switch target.network {
	case "udp4":
		packetConn := ipv4.NewPacketConn(conn)
		return func(buffer []byte) (int, *mdnsResponse, error) {
			n, control, source, err := packetConn.ReadFrom(buffer)
			response := &mdnsResponse{source: asUDPAddr(source)}
			if control != nil {
				response.ifIndex = control.IfIndex
				response.destination = append(net.IP(nil), control.Dst...)
				response.hopLimit = control.TTL
			}
			return n, response, err
		}
	case "udp6":
		packetConn := ipv6.NewPacketConn(conn)
		return func(buffer []byte) (int, *mdnsResponse, error) {
			n, control, source, err := packetConn.ReadFrom(buffer)
			response := &mdnsResponse{source: asUDPAddr(source)}
			if control != nil {
				response.ifIndex = control.IfIndex
				response.destination = append(net.IP(nil), control.Dst...)
				response.hopLimit = control.HopLimit
			}
			return n, response, err
		}
	default:
		return func([]byte) (int, *mdnsResponse, error) {
			return 0, nil, fmt.Errorf("unsupported mDNS network %q", target.network)
		}
	}
}

func asUDPAddr(addr net.Addr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	udpAddr, _ := addr.(*net.UDPAddr)
	return udpAddr
}

func validMDNSTransport(response *mdnsResponse, target mdnsTarget) bool {
	if response == nil {
		return false
	}
	if target.iface == nil || !target.addr.IP.IsMulticast() {
		return true
	}
	return response.source != nil &&
		response.source.Port == mdnsPort &&
		response.ifIndex == target.iface.Index &&
		response.destination.Equal(target.addr.IP)
}

func validMDNSMessage(response *D.Msg) bool {
	return response.Response &&
		response.Opcode == D.OpcodeQuery &&
		response.Rcode == D.RcodeSuccess
}

// mergeMDNSResponses resolves CNAME chains independently on each ingress
// interface, then returns the union of interfaces with a positive answer.
// Identical records are collapsed using the greatest observed TTL. This keeps
// same-named hosts on different links independent while allowing all distinct
// addresses to be returned to Mihomo's interface-agnostic DNS layer.
func mergeMDNSResponses(request *D.Msg, responses []mdnsResponse) (*D.Msg, bool) {
	response := &D.Msg{}
	response.SetReply(request)
	response.Authoritative = true
	response.RecursionAvailable = false

	question := request.Question[0]
	interfaceOrder := make([]int, 0)
	interfaceRecords := map[int][]D.RR{}
	for _, item := range responses {
		if item.msg == nil {
			continue
		}
		if _, exists := interfaceRecords[item.ifIndex]; !exists {
			interfaceOrder = append(interfaceOrder, item.ifIndex)
		}
		interfaceRecords[item.ifIndex] = append(interfaceRecords[item.ifIndex], item.msg.Answer...)
		interfaceRecords[item.ifIndex] = append(interfaceRecords[item.ifIndex], item.msg.Ns...)
		interfaceRecords[item.ifIndex] = append(interfaceRecords[item.ifIndex], item.msg.Extra...)
	}

	type interfaceResult struct {
		answers  []D.RR
		negative []D.RR
		positive bool
	}
	results := make([]interfaceResult, 0, len(interfaceOrder))
	hasPositive := false
	hasNegative := false
	for _, ifIndex := range interfaceOrder {
		records := interfaceRecords[ifIndex]
		rootName := canonicalMDNSName(question.Name)
		names := map[string]struct{}{rootName: {}}
		orderedNames := []string{rootName}
		cnameOwners := map[string]struct{}{}
		cnameAnswers := make([]D.RR, 0)
		for nameIndex := 0; nameIndex < len(orderedNames); nameIndex++ {
			name := orderedNames[nameIndex]
			for _, record := range records {
				cname, ok := record.(*D.CNAME)
				if !ok || cname.Hdr.Class&mdnsClassMask != D.ClassINET {
					continue
				}
				owner := canonicalMDNSName(cname.Hdr.Name)
				if owner != name {
					continue
				}
				cnameOwners[owner] = struct{}{}
				cnameAnswers = append(cnameAnswers, record)
				target := canonicalMDNSName(cname.Target)
				if _, ok = names[target]; !ok {
					names[target] = struct{}{}
					orderedNames = append(orderedNames, target)
				}
			}
		}

		result := interfaceResult{answers: cnameAnswers}
		if (question.Qtype == D.TypeCNAME || question.Qtype == D.TypeANY) && len(cnameAnswers) > 0 {
			result.positive = true
		}
		for _, name := range orderedNames {
			for _, record := range records {
				header := record.Header()
				if header.Class&mdnsClassMask != D.ClassINET ||
					canonicalMDNSName(header.Name) != name {
					continue
				}
				switch {
				case header.Rrtype == D.TypeCNAME:
					// CNAMEs were appended above in chain order.
				case (header.Rrtype == question.Qtype || question.Qtype == D.TypeANY) &&
					header.Rrtype != D.TypeNSEC:
					result.answers = append(result.answers, record)
					result.positive = true
				case header.Rrtype == D.TypeNSEC:
					if _, hasCNAME := cnameOwners[name]; !hasCNAME {
						if nsec, ok := record.(*D.NSEC); ok && mdnsNSECExcludes(nsec, question.Qtype) {
							result.negative = append(result.negative, record)
						}
					}
				}
			}
		}
		if result.positive {
			hasPositive = true
		} else if len(result.negative) > 0 {
			hasNegative = true
		}
		results = append(results, result)
	}

	answerSeen := map[string]int{}
	negativeSeen := map[string]int{}
	for _, result := range results {
		if hasPositive {
			if !result.positive {
				continue
			}
			for _, record := range result.answers {
				appendMDNSRecord(&response.Answer, answerSeen, record)
			}
		} else if hasNegative && len(result.negative) > 0 {
			for _, record := range result.answers {
				appendMDNSRecord(&response.Answer, answerSeen, record)
			}
			for _, record := range result.negative {
				appendMDNSRecord(&response.Ns, negativeSeen, record)
			}
		}
	}
	return response, hasPositive || hasNegative
}

func mdnsNSECExcludes(nsec *D.NSEC, qtype uint16) bool {
	if qtype == D.TypeANY {
		return false
	}
	for _, existingType := range nsec.TypeBitMap {
		if existingType == qtype {
			return false
		}
	}
	return true
}

func appendMDNSRecord(records *[]D.RR, seen map[string]int, record D.RR) {
	record = D.Copy(record)
	record.Header().Class &= mdnsClassMask
	keyRecord := D.Copy(record)
	keyRecord.Header().Ttl = 0
	key := strings.ToLower(keyRecord.String())
	if index, ok := seen[key]; ok {
		if (*records)[index].Header().Ttl < record.Header().Ttl {
			(*records)[index].Header().Ttl = record.Header().Ttl
		}
		return
	}
	seen[key] = len(*records)
	*records = append(*records, record)
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
