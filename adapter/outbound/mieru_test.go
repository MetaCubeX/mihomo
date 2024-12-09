package outbound

import "testing"

func TestNewMieru(t *testing.T) {
	testCases := []struct {
		option       MieruOption
		wantBaseAddr string
	}{
		{
			option: MieruOption{
				Name:      "test",
				Server:    "1.2.3.4",
				Port:      10000,
				Transport: "TCP",
				UserName:  "test",
				Password:  "test",
			},
			wantBaseAddr: "1.2.3.4:10000",
		},
		{
			option: MieruOption{
				Name:      "test",
				Server:    "2001:db8::1",
				PortRange: "10001-10002",
				Transport: "TCP",
				UserName:  "test",
				Password:  "test",
			},
			wantBaseAddr: "[2001:db8::1]:10001",
		},
		{
			option: MieruOption{
				Name:      "test",
				Server:    "example.com",
				Port:      10003,
				Transport: "TCP",
				UserName:  "test",
				Password:  "test",
			},
			wantBaseAddr: "example.com:10003",
		},
	}

	for _, testCase := range testCases {
		mieru, err := NewMieru(testCase.option)
		if err != nil {
			t.Error(err)
		}
		if mieru.addr != testCase.wantBaseAddr {
			t.Errorf("got addr %q, want %q", mieru.addr, testCase.wantBaseAddr)
		}
	}
}

func TestBeginAndEndPortFromPortRange(t *testing.T) {
	testCases := []struct {
		input  string
		begin  int
		end    int
		hasErr bool
	}{
		{"1-10", 1, 10, false},
		{"1000-2000", 1000, 2000, false},
		{"65535-65535", 65535, 65535, false},
		{"1", 0, 0, true},
		{"1-", 0, 0, true},
		{"-10", 0, 0, true},
		{"a-b", 0, 0, true},
		{"1-b", 0, 0, true},
		{"a-10", 0, 0, true},
	}

	for _, testCase := range testCases {
		begin, end, err := beginAndEndPortFromPortRange(testCase.input)
		if testCase.hasErr {
			if err == nil {
				t.Errorf("beginAndEndPortFromPortRange(%s) should return an error", testCase.input)
			}
		} else {
			if err != nil {
				t.Errorf("beginAndEndPortFromPortRange(%s) should not return an error, but got %v", testCase.input, err)
			}
			if begin != testCase.begin {
				t.Errorf("beginAndEndPortFromPortRange(%s) begin port mismatch, got %d, want %d", testCase.input, begin, testCase.begin)
			}
			if end != testCase.end {
				t.Errorf("beginAndEndPortFromPortRange(%s) end port mismatch, got %d, want %d", testCase.input, end, testCase.end)
			}
		}
	}
}
