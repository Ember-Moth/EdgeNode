// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !linux

package ktls

import "crypto/tls"

// Supported 报告本平台是否包含 kTLS 密钥提取能力。
// kTLS 依赖 Linux 内核的 TLS ULP,仅在 Linux 上编译实现;其它平台返回 false。
func Supported() bool { return false }

// EnableServerTX 在未启用 ktls 构建标签时不可用
func EnableServerTX(conn *tls.Conn) (fd int, err error) {
	return -1, ErrUnsupported
}

// SelfTest 在未启用 ktls 构建标签时不可用
func SelfTest() error {
	return ErrUnsupported
}
