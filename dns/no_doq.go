//go:build no_doq

package dns

import "github.com/Dreamacro/clash/log"

func newDOQ(r *Resolver, addr, proxyAdapter string) dnsClient {
	log.Fatalln("unsupported feature on the build")
	return nil
}
