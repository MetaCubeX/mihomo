package mkcp

// notifier is a utility for notifying changes. The producer may signal multiple
// times; the consumer gets notified asynchronously. Ported from xray-core
// common/signal.Notifier.
type notifier struct {
	c chan struct{}
}

func newNotifier() *notifier {
	return &notifier{c: make(chan struct{}, 1)}
}

// Signal signals a change. Never blocks.
func (n *notifier) Signal() {
	select {
	case n.c <- struct{}{}:
	default:
	}
}

// Wait returns a channel that receives on each signal. Never closed.
func (n *notifier) Wait() <-chan struct{} {
	return n.c
}

// semaphore is a counting semaphore, ported from xray-core
// common/signal/semaphore.Instance.
type semaphore struct {
	token chan struct{}
}

func newSemaphore(n int) *semaphore {
	s := &semaphore{token: make(chan struct{}, n)}
	for i := 0; i < n; i++ {
		s.token <- struct{}{}
	}
	return s
}

// Wait returns a channel for acquiring a permit.
func (s *semaphore) Wait() <-chan struct{} {
	return s.token
}

// Signal releases a permit back into the semaphore.
func (s *semaphore) Signal() {
	s.token <- struct{}{}
}
