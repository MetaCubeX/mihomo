package tailnet

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"text/tabwriter"
	"time"
)

var ErrStatusUnavailable = errors.New("proxy does not provide Tailnet status")

type StatusProvider interface {
	TailnetStatus(ctx context.Context) (Status, error)
}

type Status struct {
	Proxy           string       `json:"proxy"`
	BackendState    string       `json:"backendState"`
	MagicDNSSuffix  string       `json:"magicDNSSuffix,omitempty"`
	MagicDNSEnabled bool         `json:"magicDNSEnabled,omitempty"`
	TailscaleIPs    []string     `json:"tailscaleIPs,omitempty"`
	Self            *NodeStatus  `json:"self,omitempty"`
	Peers           []NodeStatus `json:"peers"`
}

type NodeStatus struct {
	Name         string     `json:"name"`
	HostName     string     `json:"hostName,omitempty"`
	DNSName      string     `json:"dnsName,omitempty"`
	OS           string     `json:"os,omitempty"`
	TailscaleIPs []string   `json:"tailscaleIPs,omitempty"`
	Online       bool       `json:"online"`
	LastSeen     *time.Time `json:"lastSeen,omitempty"`
	Relay        string     `json:"relay,omitempty"`
	PeerRelay    string     `json:"peerRelay,omitempty"`
	TxBytes      int64      `json:"txBytes,omitempty"`
	RxBytes      int64      `json:"rxBytes,omitempty"`
	Self         bool       `json:"self,omitempty"`
}

func (s Status) Text() string {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	if s.Self != nil {
		writeNodeStatus(tw, *s.Self)
	}
	for _, peer := range s.Peers {
		writeNodeStatus(tw, peer)
	}

	_ = tw.Flush()
	return buf.String()
}

func writeNodeStatus(tw *tabwriter.Writer, node NodeStatus) {
	name := node.Name
	if name == "" {
		name = node.HostName
	}
	if name == "" {
		name = strings.TrimRight(node.DNSName, ".")
	}
	if name == "" && len(node.TailscaleIPs) > 0 {
		name = node.TailscaleIPs[0]
	}

	status := "-"
	if node.Online {
		status = "online"
	} else if node.LastSeen != nil {
		status = "offline, last seen " + node.LastSeen.Format(time.RFC3339)
	} else if !node.Self {
		status = "offline"
	}
	if node.Relay != "" {
		status += `; relay "` + node.Relay + `"`
	}

	_, _ = tw.Write([]byte(strings.Join([]string{
		strings.Join(node.TailscaleIPs, ","),
		name,
		node.OS,
		status,
	}, "\t") + "\n"))
}
