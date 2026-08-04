// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .

// Package ktls 提供内核TLS(kTLS)卸载的套接字层封装。
//
// 作用与边界（务必阅读）：
//
// kTLS 让内核完成 TLS 记录层的加解密，从而使 sendfile(2) 等零拷贝手段可用于 TLS 连接——
// 静态文件/缓存命中可从磁盘直达网卡，不经用户态。本包实现的是这一能力的“内核侧”：
// 在一个已完成握手的 TCP fd 上通过 setsockopt 挂载 TLS ULP 并注入会话密钥。
//
// 本包不做、也无法做的事：从 Go 标准库 crypto/tls 中取出会话密钥。
// crypto/tls 的 trafficSecret 是私有字段，无任何导出 API；且 *tls.Conn 独占记录层、
// 不交出裸 fd，握手后还会用应用密钥发送 session ticket 导致记录序列号无法对齐。
// 因此要把本包接到 EdgeNode 现有的 HTTPS 连接上，需要能导出密钥的 TLS 栈——
// 打补丁的 crypto/tls，或支持 SSL_OP_ENABLE_KTLS 的 BoringSSL/OpenSSL 绑定。
// 调用方拿到 KeyMaterial 后调用 Enable* 即可，本包已就绪并有往返测试验证内核侧正确性。
package ktls

import "errors"

// ErrUnsupported 表示当前平台不支持 kTLS
var ErrUnsupported = errors.New("ktls: not supported on this platform")

// Direction kTLS 方向
type Direction int

const (
	// TX 发送方向（服务端加密 => 客户端），sendfile 零拷贝依赖此方向
	TX Direction = 1 // TLS_TX
	// RX 接收方向（客户端 => 服务端解密）
	RX Direction = 2 // TLS_RX
)

// Cipher kTLS 支持的加密套件
type Cipher int

const (
	CipherAESGCM128 Cipher = iota
	CipherAESGCM256
	CipherCHACHA20POLY1305
)

// TLSVersion TLS 版本
type TLSVersion uint16

const (
	VersionTLS12 TLSVersion = 0x0303
	VersionTLS13 TLSVersion = 0x0304
)

// KeyMaterial 一个方向的会话密钥物料。
// 各字段长度依 Cipher 而定，由 TLS 栈在握手后按密钥调度算法(HKDF-Expand-Label)导出：
//   - AES-GCM-128:  Key 16B, IV 8B, Salt 4B
//   - AES-GCM-256:  Key 32B, IV 8B, Salt 4B
//   - CHACHA20:     Key 32B, IV 12B, Salt 0B
//
// RecSeq 为该方向应用数据的起始记录序列号(8B, 大端)，TLS1.3 通常从 0 开始。
type KeyMaterial struct {
	Version TLSVersion
	Cipher  Cipher
	Key     []byte
	IV      []byte
	Salt    []byte
	RecSeq  []byte
}
