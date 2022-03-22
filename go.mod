module github.com/Dreamacro/clash

go 1.18

require (
	github.com/Dreamacro/go-shadowsocks2 v0.1.7
	github.com/dlclark/regexp2 v1.4.0
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-chi/cors v1.2.0
	github.com/go-chi/render v1.0.1
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/gorilla/websocket v1.5.0
	github.com/insomniacslk/dhcp v0.0.0-20220119180841-3c283ff8b7dd
	github.com/lucas-clemente/quic-go v0.25.0
	github.com/miekg/dns v1.1.47
	github.com/oschwald/geoip2-golang v1.6.1
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.1
	github.com/xtls/go v0.0.0-20210920065950-d4af136d3672
	go.etcd.io/bbolt v1.3.6
	go.uber.org/atomic v1.9.0
	go.uber.org/automaxprocs v1.4.0
	golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20220318055525-2edf467146b5
	golang.org/x/time v0.0.0-20220224211638-0e9765cccd65
	golang.zx2c4.com/wireguard v0.0.0-20220318042302-193cf8d6a5d6
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20220317000008-6432784c2469
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v2 v2.4.0
	gvisor.dev/gvisor v0.0.0-20220319025644-e785bfc153f5
)

require (
	github.com/cheekybits/genny v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/marten-seemann/qtls-go1-16 v0.1.4 // indirect
	github.com/marten-seemann/qtls-go1-17 v0.1.0 // indirect
	github.com/marten-seemann/qtls-go1-18 v0.1.0 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/oschwald/maxminddb-golang v1.8.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/u-root/uio v0.0.0-20220204230159-dac05f7d2cb4 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220106191415-9b9b3d81d5e3 // indirect
	golang.org/x/text v0.3.8-0.20220124021120-d1c84af989ab // indirect
	golang.org/x/tools v0.1.10 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

replace golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224 => github.com/MetaCubeX/wintun-go v0.0.0-20220319102620-bbc5e6b2015e
