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
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type dialResult struct {
	pc   net.PacketConn
	addr net.Addr
	err  error
}

type PoolClient struct {
	*ClientOption

	newClientOption *ClientOption
	dialResultMap   map[any]dialResult
	dialResultMutex *sync.Mutex
	tcpClients      *list.List[*Client]
	tcpClientsMutex *sync.Mutex
	udpClients      *list.List[*Client]
	udpClientsMutex *sync.Mutex
}

func (t *PoolClient) DialContext(ctx context.Context, metadata *C.Metadata, dialFn DialFunc, opts ...dialer.Option) (net.Conn, error) {
	newDialFn := func(ctx context.Context, opts ...dialer.Option) (pc net.PacketConn, addr net.Addr, err error) {
		return t.dial(ctx, dialFn, opts...)
	}
	var o any = *dialer.ApplyOptions(opts...)
	conn, err := t.getClient(false, o).DialContext(ctx, metadata, newDialFn, opts...)
	if errors.Is(err, TooManyOpenStreams) {
		conn, err = t.newClient(false, o).DialContext(ctx, metadata, newDialFn, opts...)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *PoolClient) DialContextWithDialer(ctx context.Context, d C.Dialer, metadata *C.Metadata, dialFn DialWithDialerFunc) (net.Conn, error) {
	newDialFn := func(ctx context.Context, opts ...dialer.Option) (pc net.PacketConn, addr net.Addr, err error) {
		return dialFn(ctx, d)
	}
	var o any = d
	conn, err := t.getClient(false, o).DialContext(ctx, metadata, newDialFn)
	if errors.Is(err, TooManyOpenStreams) {
		conn, err = t.newClient(false, o).DialContext(ctx, metadata, newDialFn)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *PoolClient) ListenPacketContext(ctx context.Context, metadata *C.Metadata, dialFn DialFunc, opts ...dialer.Option) (net.PacketConn, error) {
	newDialFn := func(ctx context.Context, opts ...dialer.Option) (pc net.PacketConn, addr net.Addr, err error) {
		return t.dial(ctx, dialFn, opts...)
	}
	var o any = *dialer.ApplyOptions(opts...)
	pc, err := t.getClient(true, o).ListenPacketContext(ctx, metadata, newDialFn, opts...)
	if errors.Is(err, TooManyOpenStreams) {
		pc, err = t.newClient(true, o).ListenPacketContext(ctx, metadata, newDialFn, opts...)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *PoolClient) ListenPacketWithDialer(ctx context.Context, d C.Dialer, metadata *C.Metadata, dialFn DialWithDialerFunc) (net.PacketConn, error) {
	newDialFn := func(ctx context.Context, opts ...dialer.Option) (pc net.PacketConn, addr net.Addr, err error) {
		return dialFn(ctx, d)
	}
	var o any = d
	pc, err := t.getClient(true, o).ListenPacketContext(ctx, metadata, newDialFn)
	if errors.Is(err, TooManyOpenStreams) {
		pc, err = t.newClient(true, o).ListenPacketContext(ctx, metadata, newDialFn)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *PoolClient) dial(ctx context.Context, dialFn DialFunc, opts ...dialer.Option) (pc net.PacketConn, addr net.Addr, err error) {
	var o any = *dialer.ApplyOptions(opts...)

	t.dialResultMutex.Lock()
	dr, ok := t.dialResultMap[o]
	t.dialResultMutex.Unlock()
	if ok {
		return dr.pc, dr.addr, dr.err
	}

	pc, addr, err = dialFn(ctx, opts...)
	if err != nil {
		return nil, nil, err
	}

	dr.pc, dr.addr, dr.err = pc, addr, err

	t.dialResultMutex.Lock()
	t.dialResultMap[o] = dr
	t.dialResultMutex.Unlock()
	return pc, addr, err
}

func (t *PoolClient) forceClose() {
	t.dialResultMutex.Lock()
	defer t.dialResultMutex.Unlock()
	for key := range t.dialResultMap {
		pc := t.dialResultMap[key].pc
		if pc != nil {
			_ = pc.Close()
		}
		delete(t.dialResultMap, key)
	}
}

func (t *PoolClient) newClient(udp bool, o any) *Client {
	clients := t.tcpClients
	clientsMutex := t.tcpClientsMutex
	if udp {
		clients = t.udpClients
		clientsMutex = t.udpClientsMutex
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	client := NewClient(t.newClientOption, udp)
	client.optionRef = o
	client.lastVisited = time.Now()

	clients.PushFront(client)
	return client
}

func (t *PoolClient) getClient(udp bool, o any) *Client {
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
			if client.optionRef == o {
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
		return t.newClient(udp, o)
	} else {
		bestClient.lastVisited = time.Now()
		return bestClient
	}
}

func NewPoolClient(clientOption *ClientOption) *PoolClient {
	p := &PoolClient{
		ClientOption:    clientOption,
		dialResultMap:   make(map[any]dialResult),
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
