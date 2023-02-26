module github.com/Dreamacro/clash

go 1.19

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	github.com/cilium/ebpf v0.9.3
	github.com/coreos/go-iptables v0.6.0
	github.com/dlclark/regexp2 v1.7.0
	github.com/go-chi/chi/v5 v5.0.8
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.2
	github.com/gofrs/uuid v4.4.0+incompatible
	github.com/google/gopacket v1.1.19
	github.com/gorilla/websocket v1.5.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/insomniacslk/dhcp v0.0.0-20221215072855-de60144f33f8
	github.com/jpillora/backoff v1.0.0
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40
	github.com/mdlayher/netlink v1.7.2-0.20221213171556-9881fafed8c7
	github.com/metacubex/quic-go v0.32.0
	github.com/metacubex/sing-shadowsocks v0.1.1-0.20230202072246-e2bef5f088c7
	github.com/metacubex/sing-tun v0.1.1-0.20230222113101-fbfa2dab826d
	github.com/metacubex/sing-wireguard v0.0.0-20230213124601-d04406a109b4
	github.com/miekg/dns v1.1.50
	github.com/mroth/weightedrand/v2 v2.0.0
	github.com/oschwald/geoip2-golang v1.8.0
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97
	github.com/sagernet/sing v0.1.8-0.20230226075703-7def9588a57c
	github.com/sagernet/sing-shadowtls v0.0.0-20230221130515-dac782ca098e
	github.com/sagernet/sing-vmess v0.1.2
	github.com/sagernet/tfo-go v0.0.0-20230207095944-549363a7327d
	github.com/sagernet/utls v0.0.0-20230220130002-c08891932056
	github.com/sagernet/wireguard-go v0.0.0-20221116151939-c99467f53f2c
	github.com/samber/lo v1.37.0
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.1
	github.com/xtls/go v0.0.0-20220914232946-0441cf4cf837
	go.etcd.io/bbolt v1.3.6
	go.uber.org/atomic v1.10.0
	go.uber.org/automaxprocs v1.5.1
	golang.org/x/crypto v0.6.0
	golang.org/x/exp v0.0.0-20221205204356-47842c84f3db
	golang.org/x/net v0.6.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.5.0
	google.golang.org/protobuf v1.28.2-0.20230118093459-a9481185b34d
	gopkg.in/yaml.v3 v3.0.1
	lukechampine.com/blake3 v1.1.7
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.15.15 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/metacubex/gvisor v0.0.0-20230222112937-bdbcd206ec65 // indirect
	github.com/onsi/ginkgo/v2 v2.2.0 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-18 v0.2.0 // indirect
	github.com/quic-go/qtls-go1-19 v0.2.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.1.0 // indirect
	github.com/sagernet/go-tun2socks v1.16.12-0.20220818015926-16cb67876a61 // indirect
	github.com/u-root/uio v0.0.0-20221213070652-c3537552635f // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	golang.org/x/mod v0.7.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	golang.org/x/tools v0.5.0 // indirect
)

replace go.uber.org/atomic v1.10.0 => github.com/metacubex/uber-atomic v0.0.0-20230202125923-feb10b770370
