package tuic

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/generics/list"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"github.com/metacubex/quic-go"
)

type dialResult struct {
	transport *quic.Transport
	addr      net.Addr
	err       error
}

type PoolClient struct {
	*ClientOption

	newClientOption *ClientOption
	dialResultMap   map[C.Dialer]dialResult
	dialResultMutex *sync.Mutex
	tcpClients      *list.List[*Client]
	tcpClientsMutex *sync.Mutex
	udpClients      *list.List[*Client]
	udpClientsMutex *sync.Mutex
}

func (t *PoolClient) DialContextWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn DialFunc) (net.Conn, error) {
	newDialFn := func(ctx context.Context, dialer C.Dialer) (transport *quic.Transport, addr net.Addr, err error) {
		return t.dial(ctx, dialer, dialFn)
	}
	conn, err := t.getClient(false, dialer).DialContextWithDialer(ctx, metadata, dialer, newDialFn)
	if errors.Is(err, TooManyOpenStreams) {
		conn, err = t.newClient(false, dialer).DialContextWithDialer(ctx, metadata, dialer, newDialFn)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *PoolClient) ListenPacketWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn DialFunc) (net.PacketConn, error) {
	newDialFn := func(ctx context.Context, dialer C.Dialer) (transport *quic.Transport, addr net.Addr, err error) {
		return t.dial(ctx, dialer, dialFn)
	}
	pc, err := t.getClient(true, dialer).ListenPacketWithDialer(ctx, metadata, dialer, newDialFn)
	if errors.Is(err, TooManyOpenStreams) {
		pc, err = t.newClient(true, dialer).ListenPacketWithDialer(ctx, metadata, dialer, newDialFn)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *PoolClient) dial(ctx context.Context, dialer C.Dialer, dialFn DialFunc) (transport *quic.Transport, addr net.Addr, err error) {
	t.dialResultMutex.Lock()
	dr, ok := t.dialResultMap[dialer]
	t.dialResultMutex.Unlock()
	if ok {
		return dr.transport, dr.addr, dr.err
	}

	transport, addr, err = dialFn(ctx, dialer)
	if err != nil {
		return nil, nil, err
	}

	if _, ok := transport.Conn.(*net.UDPConn); ok { // only cache the system's UDPConn
		transport.SetSingleUse(false) // don't close transport in each dial
		dr.transport, dr.addr, dr.err = transport, addr, err

		t.dialResultMutex.Lock()
		t.dialResultMap[dialer] = dr
		t.dialResultMutex.Unlock()
	}

	return transport, addr, err
}

func (t *PoolClient) forceClose() {
	t.dialResultMutex.Lock()
	defer t.dialResultMutex.Unlock()
	for key := range t.dialResultMap {
		transport := t.dialResultMap[key].transport
		if transport != nil {
			_ = transport.Close()
		}
		delete(t.dialResultMap, key)
	}
}

func (t *PoolClient) newClient(udp bool, dialer C.Dialer) *Client {
	clients := t.tcpClients
	clientsMutex := t.tcpClientsMutex
	if udp {
		clients = t.udpClients
		clientsMutex = t.udpClientsMutex
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	client := NewClient(t.newClientOption, udp)
	client.dialerRef = dialer
	client.lastVisited = time.Now()

	clients.PushFront(client)
	return client
}

func (t *PoolClient) getClient(udp bool, dialer C.Dialer) *Client {
	clients := t.tcpClients
	clientsMutex := t.tcpClientsMutex
	if udp {
		clients = t.udpClients
		clientsMutex = t.udpClientsMutex
	}
	var bestClient *Client

	func() {
		clientsMutex.Lock()
		defer clientsMutex.Unlock()
		for it := clients.Front(); it != nil; {
			client := it.Value
			if client == nil {
				next := it.Next()
				clients.Remove(it)
				it = next
				continue
			}
			if client.dialerRef == dialer {
				if bestClient == nil {
					bestClient = client
				} else {
					if client.openStreams.Load() < bestClient.openStreams.Load() {
						bestClient = client
					}
				}
			}
			it = it.Next()
		}
	}()
	for it := clients.Front(); it != nil; {
		client := it.Value
		if client != bestClient && client.openStreams.Load() == 0 && time.Now().Sub(client.lastVisited) > 30*time.Minute {
			client.Close()
			next := it.Next()
			clients.Remove(it)
			it = next
			continue
		}
		it = it.Next()
	}

	if bestClient == nil {
		return t.newClient(udp, dialer)
	} else {
		bestClient.lastVisited = time.Now()
		return bestClient
	}
}

func NewPoolClient(clientOption *ClientOption) *PoolClient {
	p := &PoolClient{
		ClientOption:    clientOption,
		dialResultMap:   make(map[C.Dialer]dialResult),
		dialResultMutex: &sync.Mutex{},
		tcpClients:      list.New[*Client](),
		tcpClientsMutex: &sync.Mutex{},
		udpClients:      list.New[*Client](),
		udpClientsMutex: &sync.Mutex{},
	}
	newClientOption := *clientOption
	p.newClientOption = &newClientOption
	runtime.SetFinalizer(p, closeClientPool)
	log.Debugln("New Tuic PoolClient at %p", p)
	return p
}

func closeClientPool(client *PoolClient) {
	log.Debugln("Close Tuic PoolClient at %p", client)
	client.forceClose()
}
