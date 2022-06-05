//go:build !no_script

package js

import (
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/require"
	"net/netip"
)

type Context struct {
	runtime *goja.Runtime
}

func (c *Context) Resolve(host string, dnsType C.DnsType) []string {
	var ips []string
	var ipAddrs []netip.Addr
	var err error
	switch dnsType {
	case C.IPv4:
		ipAddrs, err = resolver.ResolveAllIPv4(host)
	case C.IPv6:
		ipAddrs, err = resolver.ResolveAllIPv6(host)
	case C.All:
		ipAddrs, err = resolver.ResolveAllIP(host)
	}

	if err != nil {
		log.Errorln("Script resolve %s failed, error: %v", host, err)
		return ips
	}

	for _, addr := range ipAddrs {
		ips = append(ips, addr.String())
	}

	return ips
}

func newContext() require.ModuleLoader {
	return func(runtime *goja.Runtime, object *goja.Object) {
		ctx := Context{
			runtime: runtime,
		}

		o := object.Get("exports").(*goja.Object)
		o.Set("resolve", func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) < 1 {
				return runtime.ToValue([]string{})
			}

			host := call.Argument(0).String()
			dnsType := C.IPv4
			if len(call.Arguments) == 2 {
				dnsType = int(call.Argument(1).ToInteger())
			}

			ips := ctx.Resolve(host, C.DnsType(dnsType))
			return runtime.ToValue(ips)
		})
	}
}

func enable(rt *goja.Runtime) {
	rt.Set("context", require.Require(rt, "context"))
}
