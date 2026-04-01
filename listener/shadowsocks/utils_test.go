package shadowsocks

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSSURL(t *testing.T) {
	for _, test := range []struct{ method, passwd, hosts string }{
		{method: "aes-256-gcm", passwd: "password", hosts: ":1000,:2000,:3000"},
		{method: "aes-256-gcm", passwd: "password", hosts: "127.0.0.1:1000,127.0.0.1:2000,127.0.0.1:3000"},
		{method: "aes-256-gcm", passwd: "password", hosts: "[::1]:1000,[::1]:2000,[::1]:3000"},
	} {
		addr, cipher, password, err := ParseSSURL(fmt.Sprintf("ss://%s:%s@%s", test.method, test.passwd, test.hosts))
		require.NoError(t, err)
		require.Equal(t, test.hosts, addr)
		require.Equal(t, test.method, cipher)
		require.Equal(t, test.passwd, password)
	}
}
