package core

import "testing"

func TestResetSessionLeavesTheClientOpen(t *testing.T) {
	c := &Client{}
	c.ResetSession("test")
	if c.closed {
		t.Fatal("ResetSession closed the client; the next dial would return ErrClosed instead of reconnecting")
	}
	if c.quicSession != nil {
		t.Fatal("a session appeared from nowhere")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !c.closed {
		t.Fatal("Close must stay permanent")
	}
}
