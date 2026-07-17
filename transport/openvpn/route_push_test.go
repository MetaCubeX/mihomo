package openvpn

import (
	"net/netip"
	"testing"
)

func TestParsePushReplyKeepalive(t *testing.T) {
	msg := "PUSH_REPLY,ping 10,ping-restart 60,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	if reply.PingInterval != 10 {
		t.Fatalf("expected ping interval 10, got %d", reply.PingInterval)
	}
	if reply.PingRestart != 60 {
		t.Fatalf("expected ping-restart 60, got %d", reply.PingRestart)
	}
}

func TestParsePushReplyKeepaliveMissing(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	if reply.PingInterval != 0 {
		t.Fatalf("expected ping interval 0, got %d", reply.PingInterval)
	}
	if reply.PingRestart != 0 {
		t.Fatalf("expected ping-restart 0, got %d", reply.PingRestart)
	}
}

func TestApplyPullFiltersReject(t *testing.T) {
	msg := "PUSH_REPLY,redirect-gateway,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	filters := []PullFilter{
		{Action: "reject", Text: "redirect-gateway"},
	}
	err = reply.ApplyPullFilters(filters)
	if err == nil {
		t.Fatal("expected error from reject filter")
	}
}

func TestApplyPullFiltersIgnore(t *testing.T) {
	msg := "PUSH_REPLY,redirect-gateway,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !reply.Redirect {
		t.Fatal("expected redirect-gateway to be set before filter")
	}
	filters := []PullFilter{
		{Action: "ignore", Text: "redirect-gateway"},
	}
	if err := reply.ApplyPullFilters(filters); err != nil {
		t.Fatal(err)
	}
	if reply.Redirect {
		t.Fatal("expected redirect-gateway to be cleared after ignore filter")
	}
}

func TestApplyPullFiltersAccept(t *testing.T) {
	msg := "PUSH_REPLY,redirect-gateway,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	filters := []PullFilter{
		{Action: "accept", Text: "redirect-gateway"},
	}
	if err := reply.ApplyPullFilters(filters); err != nil {
		t.Fatal(err)
	}
	if !reply.Redirect {
		t.Fatal("expected redirect-gateway to remain after accept filter")
	}
}

func TestApplyPullFiltersNoMatch(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	filters := []PullFilter{
		{Action: "reject", Text: "route "},
	}
	if err := reply.ApplyPullFilters(filters); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRouteNoPull(t *testing.T) {
	msg := "PUSH_REPLY,route 10.8.0.0 255.255.255.0,redirect-gateway,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Routes) == 0 {
		t.Fatal("expected routes before ApplyRouteNoPull")
	}
	if !reply.Redirect {
		t.Fatal("expected redirect before ApplyRouteNoPull")
	}
	reply.ApplyRouteNoPull(true)
	if len(reply.Routes) != 0 {
		t.Fatalf("expected routes cleared, got %d", len(reply.Routes))
	}
	if reply.Redirect {
		t.Fatal("expected redirect cleared after route-no-pull")
	}
}

func TestMergeLocalRoutes(t *testing.T) {
	msg := "PUSH_REPLY,route 10.8.0.0 255.255.255.0,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	localRoute, _ := netip.ParsePrefix("192.168.1.0/24")
	reply.MergeLocalRoutes([]netip.Prefix{localRoute})
	if len(reply.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(reply.Routes))
	}
}
