package udp

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/transport/hysteria/obfs"
	"github.com/metacubex/mihomo/transport/hysteria/utils"

	"github.com/metacubex/randv2"
)

const (
	packetQueueSize = 1024
)

// ObfsUDPHopClientPacketConn is the UDP port-hopping packet connection for client side.
// It hops to a different local & server port every once in a while.
type ObfsUDPHopClientPacketConn struct {
	serverAddr  net.Addr // Combined udpHopAddr
	serverAddrs []net.Addr
	hopInterval time.Duration

	obfs obfs.Obfuscator

	connMutex   sync.RWMutex
	prevConn    net.PacketConn
	currentConn net.PacketConn
	addrIndex   int

	readBufferSize  int
	writeBufferSize int

	recvQueue chan *udpPacket
	closeChan chan struct{}
	closed    bool

	bufPool sync.Pool
}

type udpHopAddr string

func (a *udpHopAddr) Network() string {
	return "udp-hop"
}

func (a *udpHopAddr) String() string {
	return string(*a)
}

type udpPacket struct {
	buf  []byte
	n    int
	addr net.Addr
}

func NewObfsUDPHopClientPacketConn(server string, serverPorts string, hopInterval time.Duration, obfs obfs.Obfuscator, dialer utils.PacketDialer) (net.PacketConn, error) {
	ports, err := parsePorts(serverPorts)
	if err != nil {
		return nil, err
	}
	// Resolve the server IP address, then attach the ports to UDP addresses
	rAddr, err := dialer.RemoteAddr(server)
	if err != nil {
		return nil, err
	}
	ip, _, err := net.SplitHostPort(rAddr.String())
	if err != nil {
		return nil, err
	}
	serverAddrs := make([]net.Addr, len(ports))
	for i, port := range ports {
		serverAddrs[i] = &net.UDPAddr{
			IP:   net.ParseIP(ip),
			Port: int(port),
		}
	}
	hopAddr := udpHopAddr(server)
	conn := &ObfsUDPHopClientPacketConn{
		serverAddr:  &hopAddr,
		serverAddrs: serverAddrs,
		hopInterval: hopInterval,
		obfs:        obfs,
		addrIndex:   randv2.IntN(len(serverAddrs)),
		recvQueue:   make(chan *udpPacket, packetQueueSize),
		closeChan:   make(chan struct{}),
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, udpBufferSize)
			},
		},
	}
	curConn, err := dialer.ListenPacket(rAddr)
	if err != nil {
		return nil, err
	}
	if obfs != nil {
		conn.currentConn = NewObfsUDPConn(curConn, obfs)
	} else {
		conn.currentConn = curConn
	}
	go conn.recvRoutine(conn.currentConn)
	go conn.hopRoutine(dialer, rAddr)
	if _, ok := conn.currentConn.(syscall.Conn); ok {
		return &ObfsUDPHopClientPacketConnWithSyscall{conn}, nil
	}
	return conn, nil
}

func (c *ObfsUDPHopClientPacketConn) recvRoutine(conn net.PacketConn) {
	for {
		buf := c.bufPool.Get().([]byte)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		select {
		case c.recvQueue <- &udpPacket{buf, n, addr}:
		default:
			// Drop the packet if the queue is full
			c.bufPool.Put(buf)
		}
	}
}

func (c *ObfsUDPHopClientPacketConn) hopRoutine(dialer utils.PacketDialer, rAddr net.Addr) {
	ticker := time.NewTicker(c.hopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.hop(dialer, rAddr)
		case <-c.closeChan:
			return
		}
	}
}

func (c *ObfsUDPHopClientPacketConn) hop(dialer utils.PacketDialer, rAddr net.Addr) {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	if c.closed {
		return
	}
	newConn, err := dialer.ListenPacket(rAddr)
	if err != nil {
		// Skip this hop if failed to listen
		return
	}
	// Close prevConn,
	// prevConn <- currentConn
	// currentConn <- newConn
	// update addrIndex
	//
	// We need to keep receiving packets from the previous connection,
	// because otherwise there will be packet loss due to the time gap
	// between we hop to a new port and the server acknowledges this change.
	if c.prevConn != nil {
		_ = c.prevConn.Close() // recvRoutine will exit on error
	}
	c.prevConn = c.currentConn
	if c.obfs != nil {
		c.currentConn = NewObfsUDPConn(newConn, c.obfs)
	} else {
		c.currentConn = newConn
	}
	// Set buffer sizes if previously set
	if c.readBufferSize > 0 {
		_ = trySetPacketConnReadBuffer(c.currentConn, c.readBufferSize)
	}
	if c.writeBufferSize > 0 {
		_ = trySetPacketConnWriteBuffer(c.currentConn, c.writeBufferSize)
	}
	go c.recvRoutine(c.currentConn)
	c.addrIndex = randv2.IntN(len(c.serverAddrs))
}

func (c *ObfsUDPHopClientPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case p := <-c.recvQueue:
			/*
				// Check if the packet is from one of the server addresses
				for _, addr := range c.serverAddrs {
					if addr.String() == p.addr.String() {
						// Copy the packet to the buffer
						n := copy(b, p.buf[:p.n])
						c.bufPool.Put(p.buf)
						return n, c.serverAddr, nil
					}
				}
				// Drop the packet, continue
				c.bufPool.Put(p.buf)
			*/
			// The above code was causing performance issues when the range is large,
			// so we skip the check for now. Should probably still check by using a map
			// or something in the future.
			n := copy(b, p.buf[:p.n])
			c.bufPool.Put(p.buf)
			return n, c.serverAddr, nil
		case <-c.closeChan:
			return 0, nil, net.ErrClosed
		}
		// Ignore packets from other addresses
	}
}

func (c *ObfsUDPHopClientPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	/*
		// Check if the address is the server address
		if addr.String() != c.serverAddr.String() {
			return 0, net.ErrWriteToConnected
		}
	*/
	// Skip the check for now, always write to the server
	return c.currentConn.WriteTo(b, c.serverAddrs[c.addrIndex])
}

func (c *ObfsUDPHopClientPacketConn) Close() error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	if c.closed {
		return nil
	}
	// Close prevConn and currentConn
	// Close closeChan to unblock ReadFrom & hopRoutine
	// Set closed flag to true to prevent double close
	if c.prevConn != nil {
		_ = c.prevConn.Close()
	}
	err := c.currentConn.Close()
	close(c.closeChan)
	c.closed = true
	c.serverAddrs = nil // For GC
	return err
}

func (c *ObfsUDPHopClientPacketConn) LocalAddr() net.Addr {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()
	return c.currentConn.LocalAddr()
}

func (c *ObfsUDPHopClientPacketConn) SetReadDeadline(t time.Time) error {
	// Not supported
	return nil
}

func (c *ObfsUDPHopClientPacketConn) SetWriteDeadline(t time.Time) error {
	// Not supported
	return nil
}

func (c *ObfsUDPHopClientPacketConn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *ObfsUDPHopClientPacketConn) SetReadBuffer(bytes int) error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	c.readBufferSize = bytes
	if c.prevConn != nil {
		_ = trySetPacketConnReadBuffer(c.prevConn, bytes)
	}
	return trySetPacketConnReadBuffer(c.currentConn, bytes)
}

func (c *ObfsUDPHopClientPacketConn) SetWriteBuffer(bytes int) error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	c.writeBufferSize = bytes
	if c.prevConn != nil {
		_ = trySetPacketConnWriteBuffer(c.prevConn, bytes)
	}
	return trySetPacketConnWriteBuffer(c.currentConn, bytes)
}

func trySetPacketConnReadBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetReadBuffer(bytes int) error
	})
	if ok {
		return sc.SetReadBuffer(bytes)
	}
	return nil
}

func trySetPacketConnWriteBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetWriteBuffer(bytes int) error
	})
	if ok {
		return sc.SetWriteBuffer(bytes)
	}
	return nil
}

type ObfsUDPHopClientPacketConnWithSyscall struct {
	*ObfsUDPHopClientPacketConn
}

func (c *ObfsUDPHopClientPacketConnWithSyscall) SyscallConn() (syscall.RawConn, error) {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()
	sc, ok := c.currentConn.(syscall.Conn)
	if !ok {
		return nil, errors.New("not supported")
	}
	return sc.SyscallConn()
}

// parsePorts parses the multi-port server address and returns the host and ports.
// Supports both comma-separated single ports and dash-separated port ranges.
// Format: "host:port1,port2-port3,port4"
func parsePorts(serverPorts string) (ports []uint16, err error) {
	portStrs := strings.Split(serverPorts, ",")
	for _, portStr := range portStrs {
		if strings.Contains(portStr, "-") {
			// Port range
			portRange := strings.Split(portStr, "-")
			if len(portRange) != 2 {
				return nil, net.InvalidAddrError("invalid port range")
			}
			start, err := strconv.ParseUint(portRange[0], 10, 16)
			if err != nil {
				return nil, net.InvalidAddrError("invalid port range")
			}
			end, err := strconv.ParseUint(portRange[1], 10, 16)
			if err != nil {
				return nil, net.InvalidAddrError("invalid port range")
			}
			if start > end {
				start, end = end, start
			}
			for i := start; i <= end; i++ {
				ports = append(ports, uint16(i))
			}
		} else {
			// Single port
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return nil, net.InvalidAddrError("invalid port")
			}
			ports = append(ports, uint16(port))
		}
	}
	if len(ports) == 0 {
		return nil, net.InvalidAddrError("invalid port")
	}
	return ports, nil
}
