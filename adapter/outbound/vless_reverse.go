package outbound

import (
	"context"
	"net"

	C "github.com/metacubex/mihomo/constant"
)

// RvsSentinel —— DialReverse 用的哨兵目标域。parseVlessAddr(见 patch 0002e)见到它
// 就返回 DstAddr{Rvs:true},使 VLESS 发 Rvs 命令(0x04)且不写地址端口。
// 取值同 Xray 内部 v1.rvs.cool,仅作触发,不会被真解析。
const RvsSentinel = "v1.rvs.cool"

// DialReverse 建一条 VLESS-Rvs 反向连接流,供反向代理 Bridge 使用。
//
// 复用 mihomo VLESS 完整传输层(REALITY/TLS/ws/grpc)与 VLESS StreamConn——只把内层
// 命令换成 Rvs、目标地址省略。建流后立即 flush VLESS 请求头:Bridge 侧在此流上跑
// Mux.cool 服务端(先读后写),若不主动 flush,Portal 收不到 VLESS 头 → 不发 mux 帧 →
// 双方死锁(见蓝图 gotcha #2)。
//
// 前提:该 VLESS 出站的 flow 应为空(非 xtls-rprx-vision)。Xray Portal 对 Rvs+空 flow
// 接受;若用 Vision,则整条 mux 流被 Vision 包裹,需另行处理(S5)。
func (v *Vless) DialReverse(ctx context.Context) (net.Conn, error) {
	c, err := v.dialContext(ctx)
	if err != nil {
		return nil, err
	}
	// 目标用哨兵 → parseVlessAddr 返回 DstAddr{Rvs:true};传输层只连 v.addr,不受目标影响。
	md := &C.Metadata{NetWork: C.TCP, Host: RvsSentinel}
	c, err = v.StreamConnContext(ctx, c, md)
	if err != nil {
		return nil, err
	}
	// flush VLESS-Rvs 头(惰性发头 → 主动触发一次空写)。
	if _, err = c.Write([]byte{}); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}
