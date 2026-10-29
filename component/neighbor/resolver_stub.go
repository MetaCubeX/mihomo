//go:build !linux || android

package neighbor

const Supported = false

func openBackend() (backend, error) { return nil, ErrUnsupported }

func openQueryBackend() (queryBackend, error) { return nil, ErrUnsupported }
