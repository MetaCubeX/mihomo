package networkpolicy

// Network is a single entry under the YAML networks: list.
type Network struct {
	Name    string
	Matcher Matcher
}

// Match scans networks in order and returns the first network whose matcher
// hits ctx (first-match wins; list order is the priority mechanism).
// Returns ("", false) when no network matches or ctx is nil.
func Match(networks []Network, ctx *NetworkContext) (string, bool) {
	if ctx == nil {
		return "", false
	}
	for i := range networks {
		if networks[i].Matcher != nil && networks[i].Matcher.Match(ctx) {
			return networks[i].Name, true
		}
	}
	return "", false
}
