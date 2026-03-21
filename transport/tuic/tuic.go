package tuic

import (
	"github.com/metacubex/mihomo/transport/tuic/common"
	v4 "github.com/metacubex/mihomo/transport/tuic/v4"
	v5 "github.com/metacubex/mihomo/transport/tuic/v5"
)

type ClientOptionV4 = v4.ClientOption
type ClientOptionV5 = v5.ClientOption

type Client = common.Client

func NewClientV4(clientOption *ClientOptionV4, udp bool, dialFn DialFunc) Client {
	return v4.NewClient(clientOption, udp, dialFn)
}

func NewClientV5(clientOption *ClientOptionV5, udp bool, dialFn DialFunc) Client {
	return v5.NewClient(clientOption, udp, dialFn)
}

type DialFunc = common.DialFunc

var TooManyOpenStreams = common.TooManyOpenStreams

const DefaultStreamReceiveWindow = common.DefaultStreamReceiveWindow
const DefaultConnectionReceiveWindow = common.DefaultConnectionReceiveWindow

var GenTKN = v4.GenTKN
var PacketOverHeadV4 = v4.PacketOverHead
var PacketOverHeadV5 = v5.PacketOverHead
var MaxFragSizeV5 = v5.MaxFragSize

type UdpRelayMode = common.UdpRelayMode

const (
	QUIC   = common.QUIC
	NATIVE = common.NATIVE
)
