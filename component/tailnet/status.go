package tailnet

import (
	"bytes"
	"context"
	"errors"
	"strconv"
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
	Name           string     `json:"name"`
	HostName       string     `json:"hostName,omitempty"`
	DNSName        string     `json:"dnsName,omitempty"`
	OS             string     `json:"os,omitempty"`
	TailscaleIPs   []string   `json:"tailscaleIPs,omitempty"`
	Online         bool       `json:"online"`
	Active         bool       `json:"active"`
	LastSeen       *time.Time `json:"lastSeen,omitempty"`
	Addrs          []string   `json:"addrs,omitempty"`
	CurAddr        string     `json:"curAddr,omitempty"`
	Relay          string     `json:"relay,omitempty"`
	PeerRelay      string     `json:"peerRelay,omitempty"`
	ExitNode       bool       `json:"exitNode,omitempty"`
	ExitNodeOption bool       `json:"exitNodeOption,omitempty"`
	TxBytes        int64      `json:"txBytes,omitempty"`
	RxBytes        int64      `json:"rxBytes,omitempty"`
	Self           bool       `json:"self,omitempty"`
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

	status := nodeStatusText(node)

	_, _ = tw.Write([]byte(strings.Join([]string{
		strings.Join(node.TailscaleIPs, ","),
		name,
		node.OS,
		status,
	}, "\t") + "\n"))
}

func nodeStatusText(node NodeStatus) string {
	anyTraffic := node.TxBytes != 0 || node.RxBytes != 0
	offline := ""
	if !node.Online {
		offline = "; offline" + lastSeenText(node.LastSeen)
	}

	var parts []string
	if !node.Active {
		switch {
		case node.ExitNode:
			parts = append(parts, "idle", "exit node"+offline)
		case node.ExitNodeOption:
			parts = append(parts, "idle", "offers exit node"+offline)
		case anyTraffic:
			parts = append(parts, "idle"+offline)
		case !node.Online:
			parts = append(parts, "offline"+lastSeenText(node.LastSeen))
		default:
			parts = append(parts, "-")
		}
	} else {
		parts = append(parts, "active")
		switch {
		case node.ExitNode:
			parts = append(parts, "exit node")
		case node.ExitNodeOption:
			parts = append(parts, "offers exit node")
		}
		switch {
		case node.CurAddr != "":
			parts = append(parts, "direct "+node.CurAddr)
		case node.PeerRelay != "":
			parts = append(parts, "peer-relay "+node.PeerRelay)
		case node.Relay != "":
			parts = append(parts, `relay "`+node.Relay+`"`)
		}
		if !node.Online {
			parts = append(parts, strings.TrimPrefix(offline, "; "))
		}
	}

	status := strings.Join(parts, "; ")
	if anyTraffic {
		status += ", tx " + strconv.FormatInt(node.TxBytes, 10) + " rx " + strconv.FormatInt(node.RxBytes, 10)
	}
	return status
}

func lastSeenText(lastSeen *time.Time) string {
	if lastSeen == nil {
		return ""
	}
	return ", last seen " + lastSeen.Format(time.RFC3339)
}
