package core

import (
	"reflect"
	"testing"
)

func Test_fragUDPMessage(t *testing.T) {
	type args struct {
		m       udpMessage
		maxSize int
	}
	tests := []struct {
		name string
		args args
		want []udpMessage
	}{
		{
			"no frag",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    0,
					FragCount: 1,
					DataLen:   5,
					Data:      []byte("hello"),
				},
				100,
			},
			[]udpMessage{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    0,
					FragCount: 1,
					DataLen:   5,
					Data:      []byte("hello"),
				},
			},
		},
		{
			"2 frags",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    0,
					FragCount: 1,
					DataLen:   5,
					Data:      []byte("hello"),
				},
				22,
			},
			[]udpMessage{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    0,
					FragCount: 2,
					DataLen:   4,
					Data:      []byte("hell"),
				},
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    1,
					FragCount: 2,
					DataLen:   1,
					Data:      []byte("o"),
				},
			},
		},
		{
			"4 frags",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    0,
					FragCount: 1,
					DataLen:   20,
					Data:      []byte("wow wow wow lol lmao"),
				},
				23,
			},
			[]udpMessage{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    0,
					FragCount: 4,
					DataLen:   5,
					Data:      []byte("wow w"),
				},
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    1,
					FragCount: 4,
					DataLen:   5,
					Data:      []byte("ow wo"),
				},
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    2,
					FragCount: 4,
					DataLen:   5,
					Data:      []byte("w lol"),
				},
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    3,
					FragCount: 4,
					DataLen:   5,
					Data:      []byte(" lmao"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fragUDPMessage(tt.args.m, tt.args.maxSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fragUDPMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_defragger_Feed(t *testing.T) {
	d := &defragger{}
	type args struct {
		m udpMessage
	}
	tests := []struct {
		name string
		args args
		want *udpMessage
	}{
		{
			"no frag",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     123,
					FragID:    0,
					FragCount: 1,
					DataLen:   5,
					Data:      []byte("hello"),
				},
			},
			&udpMessage{
				SessionID: 123,
				HostLen:   4,
				Host:      "test",
				Port:      123,
				MsgID:     123,
				FragID:    0,
				FragCount: 1,
				DataLen:   5,
				Data:      []byte("hello"),
			},
		},
		{
			"frag 1 - 1/3",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     666,
					FragID:    0,
					FragCount: 3,
					DataLen:   5,
					Data:      []byte("hello"),
				},
			},
			nil,
		},
		{
			"frag 1 - 2/3",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     666,
					FragID:    1,
					FragCount: 3,
					DataLen:   8,
					Data:      []byte(" shitty "),
				},
			},
			nil,
		},
		{
			"frag 1 - 3/3",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     666,
					FragID:    2,
					FragCount: 3,
					DataLen:   7,
					Data:      []byte("world!!"),
				},
			},
			&udpMessage{
				SessionID: 123,
				HostLen:   4,
				Host:      "test",
				Port:      123,
				MsgID:     666,
				FragID:    0,
				FragCount: 1,
				DataLen:   20,
				Data:      []byte("hello shitty world!!"),
			},
		},
		{
			"frag 2 - 1/2",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     777,
					FragID:    0,
					FragCount: 2,
					DataLen:   5,
					Data:      []byte("hello"),
				},
			},
			nil,
		},
		{
			"frag 3 - 2/2",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     778,
					FragID:    1,
					FragCount: 2,
					DataLen:   5,
					Data:      []byte(" moto"),
				},
			},
			nil,
		},
		{
			"frag 2 - 2/2",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     777,
					FragID:    1,
					FragCount: 2,
					DataLen:   5,
					Data:      []byte(" moto"),
				},
			},
			nil,
		},
		{
			"frag 2 - 1/2 re",
			args{
				udpMessage{
					SessionID: 123,
					HostLen:   4,
					Host:      "test",
					Port:      123,
					MsgID:     777,
					FragID:    0,
					FragCount: 2,
					DataLen:   5,
					Data:      []byte("hello"),
				},
			},
			&udpMessage{
				SessionID: 123,
				HostLen:   4,
				Host:      "test",
				Port:      123,
				MsgID:     777,
				FragID:    0,
				FragCount: 1,
				DataLen:   10,
				Data:      []byte("hello moto"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.Feed(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Feed() = %v, want %v", got, tt.want)
			}
		})
	}
}
