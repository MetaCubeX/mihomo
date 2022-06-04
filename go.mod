module github.com/Dreamacro/clash

go 1.18

require (
	github.com/dlclark/regexp2 v1.4.0
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.1
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/gorilla/websocket v1.5.0
	github.com/insomniacslk/dhcp v0.0.0-20220504074936-1ca156eafb9f
	github.com/lucas-clemente/quic-go v0.27.0
	github.com/miekg/dns v1.1.49
	github.com/oschwald/geoip2-golang v1.7.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.1
	github.com/vishvananda/netlink v1.2.0-beta.0.20220404152918-5e915e014938
	github.com/xtls/go v0.0.0-20210920065950-d4af136d3672
	go.etcd.io/bbolt v1.3.6
	go.uber.org/atomic v1.9.0
	go.uber.org/automaxprocs v1.5.1
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e
	golang.org/x/exp v0.0.0-20220518171630-0b5c67f07fdf
	golang.org/x/net v0.0.0-20220526153639-5463443f8c37
	golang.org/x/sync v0.0.0-20220513210516-0976fa681c29
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a
	golang.org/x/time v0.0.0-20220411224347-583f2d630306
	golang.zx2c4.com/wireguard v0.0.0-20220407013110-ef5c587f782d
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20220328111914-004c22c5647e
	google.golang.org/protobuf v1.28.0
	gopkg.in/yaml.v2 v2.4.0
	gvisor.dev/gvisor v0.0.0-20220527053002-8ab279227ac8
)

require (
	github.com/cheekybits/genny v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/marten-seemann/qtls-go1-16 v0.1.5 // indirect
	github.com/marten-seemann/qtls-go1-17 v0.1.1 // indirect
	github.com/marten-seemann/qtls-go1-18 v0.1.1 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/oschwald/maxminddb-golang v1.9.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/u-root/uio v0.0.0-20220204230159-dac05f7d2cb4 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220106191415-9b9b3d81d5e3 // indirect
	golang.org/x/text v0.3.8-0.20220124021120-d1c84af989ab // indirect
	golang.org/x/tools v0.1.10 // indirect
	golang.org/x/xerrors v0.0.0-20220411194840-2f41105eb62f // indirect
	golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/vishvananda/netlink v1.2.0-beta.0.20220404152918-5e915e014938 => github.com/MetaCubeX/netlink v1.2.0-beta.0.20220529072258-d6853f887820
