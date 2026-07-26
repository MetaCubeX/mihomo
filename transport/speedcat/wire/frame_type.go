package wire

import "errors"

// FrameType —— 帧类型(对照 Rust frame::FrameType)。纳入 AAD,防被改型。
type FrameType byte

const (
	FrameTCPConnect   FrameType = 0x01 // C→S:目标 Addr
	FrameTCPData      FrameType = 0x02 // 双向:原始字节
	FrameTCPClose     FrameType = 0x03 // 双向:空
	FrameUDPAssociate FrameType = 0x04 // C→S:[ASSOC_ID:u16][目标 Addr]
	FrameUDPData      FrameType = 0x05 // 双向:[Addr][u16 plen][udp_payload]
	FramePadding      FrameType = 0x06 // 双向:随机字节(P2,抗流量分析)
	FramePing         FrameType = 0x07 // 双向:时间戳(控制流)
	FramePong         FrameType = 0x08 // 双向:回显时间戳(控制流)
	FrameError        FrameType = 0x09 // 双向:错误码:u8
	FrameMuxOpen      FrameType = 0x0A // C→S:[flags:u16][destination:Addr](P2)
)

// ErrUnknownFrameType 未知/保留帧类型(parse_header 拒绝,对照 Rust FrameType::from_u8 返 None)。
var ErrUnknownFrameType = errors.New("speedcat/wire: unknown frame type")

// FrameTypeFromByte 把字节转 FrameType(0x01-0x0A 合法,余 unknown;对照 Rust FrameType::from_u8)。
func FrameTypeFromByte(b byte) (FrameType, bool) {
	switch FrameType(b) {
	case FrameTCPConnect, FrameTCPData, FrameTCPClose, FrameUDPAssociate,
		FrameUDPData, FramePadding, FramePing, FramePong, FrameError, FrameMuxOpen:
		return FrameType(b), true
	default:
		return 0, false
	}
}

// ErrorCode —— ERROR 帧(0x09)payload 错误码。
type ErrorCode byte

const (
	ErrCodeVersionUnsupported ErrorCode = 0x01 // 版本不支持
	ErrCodePSKInvalid         ErrorCode = 0x02 // PSK 无效
	ErrCodeDialFailed         ErrorCode = 0x03 // 拨号失败
	ErrCodeProtocolViolation  ErrorCode = 0x04 // 协议违例
	ErrCodeCapabilityUnmet    ErrorCode = 0x05 // 能力不满足
)
