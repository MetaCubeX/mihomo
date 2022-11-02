module github.com/Dreamacro/clash

go 1.19

require (
	github.com/cilium/ebpf v0.9.3
	github.com/coreos/go-iptables v0.6.0
	github.com/database64128/tfo-go v1.1.2
	github.com/dlclark/regexp2 v1.7.0
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.2
	github.com/gofrs/uuid v4.3.0+incompatible
	github.com/google/gopacket v1.1.19
	github.com/gorilla/websocket v1.5.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/insomniacslk/dhcp v0.0.0-20221001123530-5308ebe5334c
	github.com/lucas-clemente/quic-go v0.29.1
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40
	github.com/miekg/dns v1.1.50
	github.com/oschwald/geoip2-golang v1.8.0
	github.com/sagernet/sing v0.0.0-20220929000216-9a83e35b7186
	github.com/sagernet/sing-shadowsocks v0.0.0-20220819002358-7461bb09a8f6
	github.com/sagernet/sing-tun v0.0.0-20221012082254-488c3b75f6fd
	github.com/sagernet/sing-vmess v0.0.0-20220921140858-b6a1bdee672f
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.0
	github.com/vishvananda/netlink v1.2.1-beta.2
	github.com/xtls/go v0.0.0-20220914232946-0441cf4cf837
	go.etcd.io/bbolt v1.3.6
	go.uber.org/atomic v1.10.0
	go.uber.org/automaxprocs v1.5.1
	golang.org/x/crypto v0.0.0-20220926161630-eccd6366d1be
	golang.org/x/exp v0.0.0-20220930202632-ec3f01382ef9
	golang.org/x/net v0.0.0-20221004154528-8021a29435af
	golang.org/x/sync v0.0.0-20220929204114-8fcdb60fdcc0
	golang.org/x/sys v0.0.0-20221006211917-84dc82d7e875
	google.golang.org/protobuf v1.28.1
	gopkg.in/yaml.v3 v3.0.1

)

replace github.com/vishvananda/netlink => github.com/MetaCubeX/netlink v1.2.0-beta.0.20220529072258-d6853f887820

replace github.com/lucas-clemente/quic-go => github.com/tobyxdd/quic-go v0.28.1-0.20220706211558-7780039ad599

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/cheekybits/genny v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/cpuid/v2 v2.1.1 // indirect
	github.com/marten-seemann/qpack v0.2.1 // indirect
	github.com/marten-seemann/qtls-go1-16 v0.1.5 // indirect
	github.com/marten-seemann/qtls-go1-17 v0.1.2 // indirect
	github.com/marten-seemann/qtls-go1-18 v0.1.2 // indirect
	github.com/marten-seemann/qtls-go1-19 v0.1.0 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sagernet/abx-go v0.0.0-20220819185957-dba1257d738e // indirect
	github.com/sagernet/go-tun2socks v1.16.12-0.20220818015926-16cb67876a61 // indirect
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97 // indirect
	github.com/u-root/uio v0.0.0-20220204230159-dac05f7d2cb4 // indirect
	github.com/vishvananda/netns v0.0.0-20220913150850-18c4f4234207 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/text v0.3.8-0.20220124021120-d1c84af989ab // indirect
	golang.org/x/time v0.0.0-20220922220347-f3bd1da661af // indirect
	golang.org/x/tools v0.1.12 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gvisor.dev/gvisor v0.0.0-20220901235040-6ca97ef2ce1c // indirect
	lukechampine.com/blake3 v1.1.7 // indirect
)
