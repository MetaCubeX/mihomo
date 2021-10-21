package resolver

import D "github.com/miekg/dns"

var DefaultLocalServer LocalServer

type LocalServer interface {
	ServeMsg(msg *D.Msg) (*D.Msg, error)
}

// ServeMsg with a dns.Msg, return resolve dns.Msg
func ServeMsg(msg *D.Msg) (*D.Msg, error) {
	if server := DefaultLocalServer; server != nil {
		return server.ServeMsg(msg)
	}

	return nil, ErrIPNotFound
}
