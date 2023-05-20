package net

import (
	"github.com/Dreamacro/clash/common/net/deadline"
	"github.com/Dreamacro/clash/common/net/packet"
)

type EnhancePacketConn = packet.EnhancePacketConn

var NewEnhancePacketConn = packet.NewEnhancePacketConn
var NewThreadSafePacketConn = packet.NewThreadSafePacketConn
var NewRefPacketConn = packet.NewRefPacketConn

var NewDeadlineNetPacketConn = deadline.NewNetPacketConn
var NewDeadlineEnhancePacketConn = deadline.NewEnhancePacketConn
var NewDeadlineSingPacketConn = deadline.NewSingPacketConn
var NewDeadlineEnhanceSingPacketConn = deadline.NewEnhanceSingPacketConn
