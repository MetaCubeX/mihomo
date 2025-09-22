package outbound

import (
	"reflect"
	"testing"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

func TestNewMieru(t *testing.T) {
	transportProtocol := mierupb.TransportProtocol_TCP.Enum()
	testCases := []struct {
		option       MieruOption
		wantBaseAddr string
		wantConfig   *mieruclient.ClientConfig
	}{
		{
			option: MieruOption{
				Name:      "test",
				Server:    "1.2.3.4",
				Port:      "10000",
				Transport: "TCP",
				UserName:  "test",
				Password:  "test",
			},
			wantBaseAddr: "1.2.3.4:10000",
			wantConfig: &mieruclient.ClientConfig{
				Profile: &mierupb.ClientProfile{
					ProfileName: proto.String("test"),
					User: &mierupb.User{
						Name:     proto.String("test"),
						Password: proto.String("test"),
					},
					Servers: []*mierupb.ServerEndpoint{
						{
							IpAddress: proto.String("1.2.3.4"),
							PortBindings: []*mierupb.PortBinding{
								{
									Port:     proto.Int32(10000),
									Protocol: transportProtocol,
								},
							},
						},
					},
				},
			},
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
			wantConfig: &mieruclient.ClientConfig{
				Profile: &mierupb.ClientProfile{
					ProfileName: proto.String("test"),
					User: &mierupb.User{
						Name:     proto.String("test"),
						Password: proto.String("test"),
					},
					Servers: []*mierupb.ServerEndpoint{
						{
							IpAddress: proto.String("2001:db8::1"),
							PortBindings: []*mierupb.PortBinding{
								{
									PortRange: proto.String("10001-10002"),
									Protocol:  transportProtocol,
								},
							},
						},
					},
				},
			},
		},
		{
			option: MieruOption{
				Name:      "test",
				Server:    "example.com",
				Port:      "10003",
				Transport: "TCP",
				UserName:  "test",
				Password:  "test",
			},
			wantBaseAddr: "example.com:10003",
			wantConfig: &mieruclient.ClientConfig{
				Profile: &mierupb.ClientProfile{
					ProfileName: proto.String("test"),
					User: &mierupb.User{
						Name:     proto.String("test"),
						Password: proto.String("test"),
					},
					Servers: []*mierupb.ServerEndpoint{
						{
							DomainName: proto.String("example.com"),
							PortBindings: []*mierupb.PortBinding{
								{
									Port:     proto.Int32(10003),
									Protocol: transportProtocol,
								},
							},
						},
					},
				},
			},
		},
		{
			option: MieruOption{
				Name:      "test",
				Server:    "example.com",
				Port:      "10004,10005",
				Transport: "TCP",
				UserName:  "test",
				Password:  "test",
			},
			wantBaseAddr: "example.com:10004",
			wantConfig: &mieruclient.ClientConfig{
				Profile: &mierupb.ClientProfile{
					ProfileName: proto.String("test"),
					User: &mierupb.User{
						Name:     proto.String("test"),
						Password: proto.String("test"),
					},
					Servers: []*mierupb.ServerEndpoint{
						{
							DomainName: proto.String("example.com"),
							PortBindings: []*mierupb.PortBinding{
								{
									Port:     proto.Int32(10004),
									Protocol: transportProtocol,
								},
								{
									Port:     proto.Int32(10005),
									Protocol: transportProtocol,
								},
							},
						},
					},
				},
			},
		},
		{
			option: MieruOption{
				Name:      "test",
				Server:    "example.com",
				Port:      "10006-10007,11000",
				Transport: "TCP",
				UserName:  "test",
				Password:  "test",
			},
			wantBaseAddr: "example.com:10006",
			wantConfig: &mieruclient.ClientConfig{
				Profile: &mierupb.ClientProfile{
					ProfileName: proto.String("test"),
					User: &mierupb.User{
						Name:     proto.String("test"),
						Password: proto.String("test"),
					},
					Servers: []*mierupb.ServerEndpoint{
						{
							DomainName: proto.String("example.com"),
							PortBindings: []*mierupb.PortBinding{
								{
									PortRange: proto.String("10006-10007"),
									Protocol:  transportProtocol,
								},
								{
									Port:     proto.Int32(11000),
									Protocol: transportProtocol,
								},
							},
						},
					},
				},
			},
		},
		{
			option: MieruOption{
				Name:      "test",
				Server:    "example.com",
				Port:      "10008",
				PortRange: "10009-10010",
				Transport: "TCP",
				UserName:  "test",
				Password:  "test",
			},
			wantBaseAddr: "example.com:10008",
			wantConfig: &mieruclient.ClientConfig{
				Profile: &mierupb.ClientProfile{
					ProfileName: proto.String("test"),
					User: &mierupb.User{
						Name:     proto.String("test"),
						Password: proto.String("test"),
					},
					Servers: []*mierupb.ServerEndpoint{
						{
							DomainName: proto.String("example.com"),
							PortBindings: []*mierupb.PortBinding{
								{
									Port:     proto.Int32(10008),
									Protocol: transportProtocol,
								},
								{
									PortRange: proto.String("10009-10010"),
									Protocol:  transportProtocol,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		mieru, err := NewMieru(testCase.option)
		if err != nil {
			t.Fatal(err)
		}
		config, err := mieru.client.Load()
		if err != nil {
			t.Fatal(err)
		}
		config.Dialer = nil
		if mieru.addr != testCase.wantBaseAddr {
			t.Errorf("got addr %q, want %q", mieru.addr, testCase.wantBaseAddr)
		}
		if !reflect.DeepEqual(config, testCase.wantConfig) {
			t.Errorf("got config %+v, want %+v", config, testCase.wantConfig)
		}
	}
}

func TestNewMieruError(t *testing.T) {
	testCases := []MieruOption{
		{
			Name:      "test",
			Server:    "example.com",
			Port:      "invalid",
			PortRange: "invalid",
			Transport: "TCP",
			UserName:  "test",
			Password:  "test",
		},
		{
			Name:      "test",
			Server:    "example.com",
			Port:      "",
			PortRange: "",
			Transport: "TCP",
			UserName:  "test",
			Password:  "test",
		},
	}

	for _, option := range testCases {
		_, err := NewMieru(option)
		if err == nil {
			t.Errorf("expected error for option %+v, but got nil", option)
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
		{"2000-1000", 0, 0, true},
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
