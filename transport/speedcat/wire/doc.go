// Package wire 实现 speedcat 协议线格式编解码(帧头 / 地址 / 能力位 / 帧类型)。
//
// 设计/流程:对照(协议线格式 SSOT)。所有多字节整数大端(network byte order)。
// 本包是纯逻辑零外部依赖(仅 Go 标准库),是 Go speedcat 客户端(crypto/handshake/client)的地基 ——
// 字节布局必须与 Rust 端逐位一致(协议两份实现)。
//
// dev 限制:A2 阶段一仅帧编解码;加密(AEAD/KDF)、传输(dial)、握手在后续包。
package wire
