package outbound

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

var (
	_ C.SessionResetter = (*Hysteria)(nil)
	_ C.SessionResetter = (*Hysteria2)(nil)
	_ C.SessionResetter = (*Tuic)(nil)
)

// ResetSession implements C.SessionResetter: the QUIC session is dropped and
// the client reconnects on the next dial, without becoming closed.
func (h *Hysteria) ResetSession(reason string) {
	if h.client == nil {
		return
	}
	h.client.ResetSession(reason)
}

// ResetSession implements C.SessionResetter: the sing-quic client keeps its
// options and dials a fresh QUIC connection on the next offer.
func (h *Hysteria2) ResetSession(reason string) {
	if h.client == nil {
		return
	}
	_ = h.client.CloseWithError(errors.New(reason))
}

// ResetSession implements C.SessionResetter: every pooled client, TCP and UDP,
// is closed now, open streams included, and the pool starts empty.
func (t *Tuic) ResetSession(reason string) {
	if t.client == nil {
		return
	}
	t.client.CloseAll(errors.New(reason))
}
