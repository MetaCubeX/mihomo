package http

import "net"

func (l *Listener) Listener() net.Listener {
	return l.listener
}
