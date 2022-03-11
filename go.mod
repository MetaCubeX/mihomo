module github.com/Dreamacro/clash

go 1.18

require (
	github.com/Dreamacro/go-shadowsocks2 v0.1.7
	github.com/Kr328/tun2socket v0.0.0-20211231120722-962f339492e8
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-chi/cors v1.2.0
	github.com/go-chi/render v1.0.1
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/gorilla/websocket v1.5.0
	github.com/insomniacslk/dhcp v0.0.0-20211214070828-5297eed8f489
	github.com/miekg/dns v1.1.46
	github.com/oschwald/geoip2-golang v1.6.1
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/xtls/go v0.0.0-20210920065950-d4af136d3672
	go.etcd.io/bbolt v1.3.6
	go.uber.org/atomic v1.9.0
	go.uber.org/automaxprocs v1.4.0
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20220227234510-4e6760a101f9
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	golang.zx2c4.com/wireguard v0.0.0-20220202223031-3b95c81cc178
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20220201002028-22d54a5eb477
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v2 v2.4.0
	gvisor.dev/gvisor v0.0.0-20220311014831-b314d81fbac7
)

replace github.com/Kr328/tun2socket => github.com/yaling888/tun2socket v0.0.0-20220311175825-946fa2efc456

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/oschwald/maxminddb-golang v1.8.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/u-root/uio v0.0.0-20210528114334-82958018845c // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/text v0.3.8-0.20220124021120-d1c84af989ab // indirect
	golang.org/x/tools v0.1.9 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)
