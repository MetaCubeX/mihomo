//go:build !(android && cmfa)

package dns

func UpdateIsolateHandler(resolver *Resolver, mapper *ResolverEnhancer) {
}
