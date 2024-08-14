//go:build go1.23 && unix

package net

func SupportTCPKeepAliveIdle() bool {
	return true
}

func SupportTCPKeepAliveInterval() bool {
	return true
}

func SupportTCPKeepAliveCount() bool {
	return true
}
