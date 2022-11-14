module clash-test

go 1.19

require (
	github.com/Dreamacro/clash v0.0.0
	github.com/docker/docker v20.10.17+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/miekg/dns v1.1.50
	github.com/stretchr/testify v1.8.1
	golang.org/x/net v0.1.1-0.20221102181756-a1278a7f7ee0
)

replace github.com/Dreamacro/clash => ../

replace github.com/vishvananda/netlink => github.com/MetaCubeX/netlink v1.2.0-beta.0.20220529072258-d6853f887820

replace github.com/lucas-clemente/quic-go => github.com/tobyxdd/quic-go v0.27.1-0.20220512040129-ed2a645d9218

require (
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/cheekybits/genny v1.0.0 // indirect
	github.com/cilium/ebpf v0.9.3 // indirect
	github.com/coreos/go-iptables v0.6.0 // indirect
	github.com/database64128/tfo-go v1.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dlclark/regexp2 v1.7.0 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/gofrs/uuid v4.3.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20221001123530-5308ebe5334c // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/lucas-clemente/quic-go v0.29.1 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/marten-seemann/qpack v0.3.0 // indirect
	github.com/marten-seemann/qtls-go1-16 v0.1.5 // indirect
	github.com/marten-seemann/qtls-go1-17 v0.1.1 // indirect
	github.com/marten-seemann/qtls-go1-18 v0.1.3 // indirect
	github.com/mdlayher/netlink v1.1.1 // indirect
	github.com/metacubex/sing-wireguard v0.0.0-20221109114053-16c22adda03c // indirect
	github.com/moby/term v0.0.0-20221105221325-4eb28fa6025c // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo v1.16.4 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/oschwald/geoip2-golang v1.8.0 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sagernet/abx-go v0.0.0-20220819185957-dba1257d738e // indirect
	github.com/sagernet/go-tun2socks v1.16.12-0.20220818015926-16cb67876a61 // indirect
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97 // indirect
	github.com/sagernet/sing v0.0.0-20221008120626-60a9910eefe4 // indirect
	github.com/sagernet/sing-shadowsocks v0.0.0-20220819002358-7461bb09a8f6 // indirect
	github.com/sagernet/sing-tun v0.0.0-20221012082254-488c3b75f6fd // indirect
	github.com/sagernet/sing-vmess v0.0.0-20221109021549-b446d5bdddf0 // indirect
	github.com/sagernet/wireguard-go v0.0.0-20221108054404-7c2acadba17c // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/u-root/uio v0.0.0-20210528114334-82958018845c // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	github.com/xtls/go v0.0.0-20220914232946-0441cf4cf837 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	golang.org/x/crypto v0.1.1-0.20221024173537-a3485e174077 // indirect
	golang.org/x/exp v0.0.0-20220930202632-ec3f01382ef9 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.1.1-0.20221102194838-fc697a31fa06 // indirect
	golang.org/x/text v0.4.0 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.org/x/tools v0.1.12 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/v3 v3.4.0 // indirect
	gvisor.dev/gvisor v0.0.0-20220901235040-6ca97ef2ce1c // indirect
	lukechampine.com/blake3 v1.1.7 // indirect
)
