package sing_vmess

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseVmessURL(t *testing.T) {
	for _, test := range []struct{ username, passwd, hosts string }{
		{username: "username", passwd: "password", hosts: ":1000,:2000,:3000"},
		{username: "username", passwd: "password", hosts: "127.0.0.1:1000,127.0.0.1:2000,127.0.0.1:3000"},
		{username: "username", passwd: "password", hosts: "[::1]:1000,[::1]:2000,[::1]:3000"},
	} {
		addr, username, password, err := ParseVmessURL(fmt.Sprintf("vmess://%s:%s@%s", test.username, test.passwd, test.hosts))
		require.NoError(t, err)
		require.Equal(t, test.hosts, addr)
		require.Equal(t, test.username, username)
		require.Equal(t, test.passwd, password)
	}
}
