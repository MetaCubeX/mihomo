package inbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/reverse"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vless/vision"

	"github.com/gofrs/uuid/v5"
)

// flowVision —— XTLS Vision flow 名。Bridge 用该 flow 连来时,Portal 侧套 vision server 解包。
const flowVision = "xtls-rprx-vision"

// RealityOptions —— reverse-portal 的 REALITY 服务端配置(与 mihomo/Xray 同义)。
type RealityOptions struct {
	Dest        string   `inbound:"dest,omitempty"`
	PrivateKey  string   `inbound:"private-key,omitempty"`
	ShortID     []string `inbound:"short-id,omitempty"`
	ServerNames []string `inbound:"server-names,omitempty"`
}

// ReversePortalOption —— 反向代理 Portal 侧 listener 配置。
// 监听端口,接受 Bridge 的 VLESS-Rvs 反连,握手后在连接上跑 Mux.cool 客户端 + 心跳,
// 并按 `tag` 注册到 reverse 表,供同 tag 的 reverse-portal 出站开子流下发用户流量。
//
// 配了 reality-config 则用 REALITY 终止(复用 listener/reality,包装 listener),
// 否则 security=none(裸 VLESS-Rvs 握手)。
type ReversePortalOption struct {
	BaseOption
	UUID        string         `inbound:"uuid"`
	Tag         string         `inbound:"tag"`
	TLS         bool           `inbound:"tls,omitempty"`          // 普通 TLS 层(非 reality);vision 需 TLS1.3 底层时用
	Certificate string         `inbound:"certificate,omitempty"`  // PEM 文件路径或内联;空则自签
	PrivateKey  string         `inbound:"private-key,omitempty"`  // 同上(TLS 用,非 reality)
	Reality     RealityOptions `inbound:"reality-config,omitempty"`
}

func (o ReversePortalOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type ReversePortal struct {
	*Base
	config *ReversePortalOption
	uid    uuid.UUID
	lns    []net.Listener
	closed bool
}

func NewReversePortal(options *ReversePortalOption) (*ReversePortal, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	if options.Tag == "" {
		return nil, errors.New("reverse-portal: `tag` can't be empty")
	}
	r := &ReversePortal{Base: base, config: options, uid: utils.UUIDMap(options.UUID)}
	return r, nil
}

func (r *ReversePortal) Config() C.InboundConfig { return r.config }

func (r *ReversePortal) Close() error {
	r.closed = true
	for _, ln := range r.lns {
		_ = ln.Close()
	}
	return nil
}

func (r *ReversePortal) Listen(t C.Tunnel) error {
	// 配了 REALITY 就构建 Builder(需要 tunnel,故在 Listen 里建),用它包装每个 listener。
	var rb *reality.Builder
	if r.config.Reality.PrivateKey != "" {
		var err error
		rb, err = reality.Config{
			Dest:        r.config.Reality.Dest,
			PrivateKey:  r.config.Reality.PrivateKey,
			ShortID:     r.config.Reality.ShortID,
			ServerNames: r.config.Reality.ServerNames,
			// REALITY 借证(steal-oneself)拨向 dest 的连接固定走 DIRECT——它是伪装用的
			// 真实握手,绝不能走用户的反向出站规则(否则被 rvout 吃掉、握手失败)。
			Proxy: "DIRECT",
		}.Build(t)
		if err != nil {
			return err
		}
	}
	// 普通 TLS(仅当未配 reality 且开了 tls):vision 的另一种合法底层。
	var tlsCfg *tls.Config
	if rb == nil && r.config.TLS {
		var err error
		tlsCfg, err = buildServerTLS(r.config.Certificate, r.config.PrivateKey)
		if err != nil {
			return err
		}
	}
	lc := r.ListenConfig()
	for _, addr := range strings.Split(r.RawAddress(), ",") {
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return err
		}
		if rb != nil {
			ln = rb.NewListener(ln) // REALITY 终止:Accept 到的即解密后的裸流
		} else if tlsCfg != nil {
			ln = tls.NewListener(ln, tlsCfg) // 普通 TLS 终止
		}
		r.lns = append(r.lns, ln)
		go r.acceptLoop(ln)
	}
	sec := "none"
	if rb != nil {
		sec = "reality"
	} else if tlsCfg != nil {
		sec = "tls"
	}
	log.Infoln("ReversePortal[%s] listening at: %s (tag=%s, security=%s)", r.Name(), r.Address(), r.config.Tag, sec)
	return nil
}

func (r *ReversePortal) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if r.closed {
				return
			}
			continue
		}
		go r.handle(c)
	}
}

func (r *ReversePortal) handle(c net.Conn) {
	flow, err := vlessRvsRead(c, r.uid)
	if err != nil {
		log.Warnln("ReversePortal[%s] VLESS-Rvs handshake failed: %v", r.Name(), err)
		_ = c.Close()
		return
	}

	var mc net.Conn // 交给 ClientWorker 的 mux 承载流
	if flow == flowVision {
		// Vision:不手写 [00][00],由 portalRespConn 在首个写(ClientWorker 开控制子流)时前置;
		// 再套 vision server 做 padding/去 padding(底层需 REALITY/TLS,已由 listener 层终止)。
		vc, verr := vision.NewConn(&portalRespConn{Conn: c}, c, r.uid)
		if verr != nil {
			log.Warnln("ReversePortal[%s] vision init failed: %v", r.Name(), verr)
			_ = c.Close()
			return
		}
		mc = vc
		log.Infoln("ReversePortal[%s] bridge connected (vision) from %s", r.Name(), c.RemoteAddr())
	} else {
		// 裸:立即回 [00][00] 响应头。
		if _, werr := c.Write([]byte{0x00, 0x00}); werr != nil {
			_ = c.Close()
			return
		}
		mc = c
		log.Infoln("ReversePortal[%s] bridge connected from %s", r.Name(), c.RemoteAddr())
	}
	reverse.RegisterPortalConn(r.config.Tag, mc) // 阻塞至隧道关闭
	log.Infoln("ReversePortal[%s] bridge %s disconnected", r.Name(), c.RemoteAddr())
}

// vlessRvsRead 读最简 VLESS 请求头,校验 UUID + 命令==Rvs(0x04),返回 client 的 flow(空 / vision)。
// 不写响应头(交由 handle 按 flow 决定)。布局:[1B ver=0][16B uuid][1B addonsLen][addons][1B cmd]。
func vlessRvsRead(conn net.Conn, uid uuid.UUID) (string, error) {
	head := make([]byte, 1+16+1) // version + uuid + addonsLen
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != 0 {
		return "", fmt.Errorf("unexpected vless version %d", head[0])
	}
	if !bytes.Equal(head[1:17], uid.Bytes()) {
		return "", errors.New("uuid mismatch")
	}
	flow := ""
	if addonsLen := int(head[17]); addonsLen > 0 {
		addons := make([]byte, addonsLen)
		if _, err := io.ReadFull(conn, addons); err != nil {
			return "", err
		}
		// Addons protobuf:字段1 Flow(string),wire = 0A <len> <flow>。
		if len(addons) >= 2 && addons[0] == 0x0A {
			fl := int(addons[1])
			if 2+fl <= len(addons) {
				flow = string(addons[2 : 2+fl])
			}
		}
	}
	var cmd [1]byte
	if _, err := io.ReadFull(conn, cmd[:]); err != nil {
		return "", err
	}
	if cmd[0] != 0x04 { // RequestCommandRvs
		return "", fmt.Errorf("expect Rvs command 0x04, got 0x%02x", cmd[0])
	}
	return flow, nil
}

// portalRespConn —— 在首个写时前置 VLESS 响应头 [version=0][addonsLen=0]([00][00]),
// 供 vision server 包装后由 ClientWorker 的首帧触发(对齐 sing_vless 的 serverConn)。
type portalRespConn struct {
	net.Conn
	written bool
}

func (c *portalRespConn) Write(b []byte) (int, error) {
	if !c.written {
		c.written = true
		out := make([]byte, 0, 2+len(b))
		out = append(out, 0x00, 0x00)
		out = append(out, b...)
		n, err := c.Conn.Write(out)
		if n -= 2; n < 0 {
			n = 0
		}
		return n, err
	}
	return c.Conn.Write(b)
}

var _ C.InboundListener = (*ReversePortal)(nil)
