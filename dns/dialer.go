package dns

// export functions from tunnel module

import "github.com/metacubex/mihomo/tunnel"

const RespectRules = tunnel.DnsRespectRules

type dialHandler = tunnel.DnsDialHandler

var getDialHandler = tunnel.GetDnsDialHandler
var listenPacket = tunnel.DnsListenPacket
