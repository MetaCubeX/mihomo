package net

import (
	"fmt"
	"net"
	"strings"
)

func SplitNetworkType(s string) (string, string, error) {
	var (
		shecme   string
		hostPort string
	)
	result := strings.Split(s, "://")
	if len(result) == 2 {
		shecme = result[0]
		hostPort = result[1]
	} else if len(result) == 1 {
		hostPort = result[0]
	} else {
		return "", "", fmt.Errorf("tcp/udp style error")
	}

	if len(shecme) == 0 {
		shecme = "udp"
	}

	if shecme != "tcp" && shecme != "udp" {
		return "", "", fmt.Errorf("scheme should be tcp:// or udp://")
	} else {
		return shecme, hostPort, nil
	}
}

func SplitHostPort(s string) (host, port string, hasPort bool, err error) {
	temp := s
	hasPort = true

	if !strings.Contains(s, ":") && !strings.Contains(s, "]:") {
		temp += ":0"
		hasPort = false
	}

	host, port, err = net.SplitHostPort(temp)
	return
}
