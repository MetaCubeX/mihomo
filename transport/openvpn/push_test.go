package openvpn

import (
	"strings"
	"testing"
	"time"
)

func TestPushReplyContinuation(t *testing.T) {
	part1 := "PUSH_REPLY,route 198.51.100.0 255.255.255.0,dhcp-option DNS 203.0.113.10,push-continuation 2"
	part2 := "PUSH_REPLY,ifconfig 198.51.100.44 255.255.255.0,peer-id 7,push-continuation 1"

	options1, continuation1 := splitPushReplyOptions(part1)
	if continuation1 != 2 {
		t.Fatalf("unexpected first continuation: %d", continuation1)
	}
	options2, continuation2 := splitPushReplyOptions(part2)
	if continuation2 != 1 {
		t.Fatalf("unexpected second continuation: %d", continuation2)
	}
	combined := joinPushReplyOptions(append(options1, options2...))
	if strings.Contains(combined, "push-continuation") {
		t.Fatalf("combined push reply should not contain continuation markers: %s", combined)
	}

	reply, err := ParsePushReply(combined)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Prefixes) != 1 || reply.PeerID != 7 || len(reply.DNS) != 1 {
		t.Fatalf("unexpected parsed continuation reply: %#v", reply)
	}
}

func TestParsePushReplyKeepaliveAndRekeyOptions(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,ifconfig 198.51.100.2 255.255.255.0,peer-id 9,ping 10,ping-restart 60,reneg-sec 3600,inactive 7200 0,explicit-exit-notify")
	if err != nil {
		t.Fatal(err)
	}
	if reply.PingInterval != 10*time.Second {
		t.Fatalf("unexpected ping interval: %s", reply.PingInterval)
	}
	if reply.PingRestart != time.Minute {
		t.Fatalf("unexpected ping restart: %s", reply.PingRestart)
	}
	if reply.RenegotiateAfter != time.Hour {
		t.Fatalf("unexpected reneg-sec: %s", reply.RenegotiateAfter)
	}
	if reply.InactiveAfter != 2*time.Hour {
		t.Fatalf("unexpected inactive timeout: %s", reply.InactiveAfter)
	}
	if !reply.ExplicitExitNotify {
		t.Fatal("expected explicit-exit-notify to be parsed")
	}
}
