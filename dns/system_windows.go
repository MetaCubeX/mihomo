//go:build windows

package dns

func loadSystemResolver() (clients []dnsClient, err error) {
	return nil, errors.New("system resolver is not yet supported on Windows")
}
