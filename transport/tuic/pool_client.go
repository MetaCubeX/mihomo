package tuic

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/generics/list"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
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

func (t *PoolClient) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (net.Conn, error) {
	conn, err := t.getClient(false, opts...).DialContext(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		conn, err = t.newClient(false, opts...).DialContext(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return conn, err
}

func (t *PoolClient) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (net.PacketConn, error) {
	pc, err := t.getClient(true, opts...).ListenPacketContext(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		pc, err = t.newClient(false, opts...).ListenPacketContext(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return pc, nil
}

func (t *PoolClient) dial(ctx context.Context, opts ...dialer.Option) (pc net.PacketConn, addr net.Addr, err error) {
	var o any = *dialer.ApplyOptions(opts...)

	t.dialResultMutex.Lock()
	dr, ok := t.dialResultMap[o]
	t.dialResultMutex.Unlock()
	if ok {
		return dr.pc, dr.addr, dr.err
	}

	pc, addr, err = t.DialFn(ctx, opts...)
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

func (t *PoolClient) newClient(udp bool, opts ...dialer.Option) *Client {
	clients := t.tcpClients
	clientsMutex := t.tcpClientsMutex
	if udp {
		clients = t.udpClients
		clientsMutex = t.udpClientsMutex
	}

	var o any = *dialer.ApplyOptions(opts...)

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	client := NewClient(t.newClientOption, udp)
	client.poolRef = t // make sure pool has a reference
	client.optionRef = o
	client.lastVisited = time.Now()

	clients.PushFront(client)
	return client
}

func (t *PoolClient) getClient(udp bool, opts ...dialer.Option) *Client {
	clients := t.tcpClients
	clientsMutex := t.tcpClientsMutex
	if udp {
		clients = t.udpClients
		clientsMutex = t.udpClientsMutex
	}

	var o any = *dialer.ApplyOptions(opts...)
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
			if client.openStreams.Load() == 0 && time.Now().Sub(client.lastVisited) > 30*time.Minute {
				client.Close()
				next := it.Next()
				clients.Remove(it)
				it = next
				continue
			}
			it = it.Next()
		}
	}()

	if bestClient == nil {
		return t.newClient(udp, opts...)
	} else {
		bestClient.lastVisited = time.Now()
		return bestClient
	}
}

func NewClientPool(clientOption *ClientOption) *PoolClient {
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
	newClientOption.DialFn = p.dial
	p.newClientOption = &newClientOption
	runtime.SetFinalizer(p, closeClientPool)
	return p
}

func closeClientPool(client *PoolClient) {
	client.forceClose()
}
