package v5

import (
	"errors"
	"testing"
)

func TestForceCloseWithoutAConnection(t *testing.T) {
	c := &clientImpl{}
	c.openStreams.Add(1)
	c.ForceClose(errors.New("test"))
	if !c.closed.Load() {
		t.Fatal("ForceClose left the client open")
	}
	if c.quicConn != nil {
		t.Fatal("a connection appeared from nowhere")
	}
	c.ForceClose(errors.New("test"))
	c.Close()
}
