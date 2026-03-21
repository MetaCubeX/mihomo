package cidr

import (
	"testing"
)

func TestIpv4(t *testing.T) {
	tests := []struct {
		name     string
		ipCidr   string
		ip       string
		expected bool
	}{
		{
			name:     "Test Case 1",
			ipCidr:   "149.154.160.0/20",
			ip:       "149.154.160.0",
			expected: true,
		},
		{
			name:     "Test Case 2",
			ipCidr:   "192.168.0.0/16",
			ip:       "10.0.0.1",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := &IpCidrSet{}
			set.AddIpCidrForString(test.ipCidr)

			result := set.IsContainForString(test.ip)
			if result != test.expected {
				t.Errorf("Expected result: %v, got: %v", test.expected, result)
			}
		})
	}
}

func TestIpv6(t *testing.T) {
	tests := []struct {
		name     string
		ipCidr   string
		ip       string
		expected bool
	}{
		{
			name:     "Test Case 1",
			ipCidr:   "2409:8000::/20",
			ip:       "2409:8087:1e03:21::27",
			expected: true,
		},
		{
			name:     "Test Case 2",
			ipCidr:   "240e::/16",
			ip:       "240e:964:ea02:100:1800::71",
			expected: true,
		},
	}
	// Add more test cases as needed

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := &IpCidrSet{}
			set.AddIpCidrForString(test.ipCidr)

			result := set.IsContainForString(test.ip)
			if result != test.expected {
				t.Errorf("Expected result: %v, got: %v", test.expected, result)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name        string
		ipCidr1     string
		ipCidr2     string
		ipCidr3     string
		expectedLen int
	}{
		{
			name:        "Test Case 1",
			ipCidr1:     "2409:8000::/20",
			ipCidr2:     "2409:8000::/21",
			ipCidr3:     "2409:8000::/48",
			expectedLen: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := &IpCidrSet{}
			set.AddIpCidrForString(test.ipCidr1)
			set.AddIpCidrForString(test.ipCidr2)
			set.Merge()

			rangesLen := len(set.rr)

			if rangesLen != test.expectedLen {
				t.Errorf("Expected len: %v, got: %v", test.expectedLen, rangesLen)
			}
		})
	}
}
