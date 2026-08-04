// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !linux

package ktls

import "crypto/tls"

// Supported 报告本构建是否包含 kTLS 密钥提取能力。
// 该能力依赖 unsafe 访问 crypto/tls 私有布局，属版本锁定的手法，默认不编译；
// 需显式以 -tags ktls 构建方可启用。
func Supported() bool { return false }

// EnableServerTX 在未启用 ktls 构建标签时不可用
func EnableServerTX(conn *tls.Conn) (fd int, err error) {
	return -1, ErrUnsupported
}

// SelfTest 在未启用 ktls 构建标签时不可用
func SelfTest() error {
	return ErrUnsupported
}
