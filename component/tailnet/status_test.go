package tailnet

import (
	"strings"
	"testing"
	"time"
)

func TestStatusText(t *testing.T) {
	lastSeen := time.Date(2026, 7, 10, 4, 0, 0, 0, time.UTC)
	status := Status{
		Self: &NodeStatus{
			Name:         "mihomo-tailnet-staging",
			OS:           "linux",
			TailscaleIPs: []string{"100.104.140.27"},
			Online:       true,
			Self:         true,
		},
		Peers: []NodeStatus{
			{
				Name:         "newvbox",
				OS:           "linux",
				TailscaleIPs: []string{"100.90.103.91"},
				Online:       true,
			},
			{
				Name:         "offline-node",
				OS:           "linux",
				TailscaleIPs: []string{"100.64.0.2"},
				LastSeen:     &lastSeen,
			},
		},
	}

	text := status.Text()
	for _, want := range []string{
		"100.104.140.27",
		"mihomo-tailnet-staging",
		"100.90.103.91",
		"newvbox",
		"offline, last seen 2026-07-10T04:00:00Z",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Text() missing %q in:\n%s", want, text)
		}
	}
}
