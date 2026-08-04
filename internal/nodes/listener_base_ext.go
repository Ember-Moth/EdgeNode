// Copyright 2023 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"crypto/tls"
	"encoding/binary"

	"github.com/cespare/xxhash/v2"
)

// calculateFingerprint 依据TLS ClientHello计算客户端指纹。
//
// 取ClientHello中客户端声明的能力（TLS版本、加密套件、椭圆曲线、点格式、签名算法、ALPN），
// 过滤掉GREASE占位值后拼接做xxhash，得到8字节指纹。
//
// 说明与局限：
//   - 这是JA3“风格”的近似，而非严格JA3：tls.ClientHelloInfo不暴露扩展(extensions)的原始列表与顺序，
//     因此指纹的区分维度弱于完整JA3；
//   - 已过滤GREASE（RFC 8701）以避免同一客户端因随机GREASE值导致指纹漂移，但无法消除扩展乱序带来的差异；
//   - 因此该指纹适合作为CC等场景在IP之外的“辅助”识别维度，不应作为唯一可信标识。
func (this *BaseListener) calculateFingerprint(clientInfo *tls.ClientHelloInfo) []byte {
	if clientInfo == nil {
		return nil
	}

	var digest = xxhash.New()
	var buf [2]byte
	var writeUint16 = func(v uint16) {
		binary.BigEndian.PutUint16(buf[:], v)
		_, _ = digest.Write(buf[:])
	}

	// TLS支持的版本（过滤GREASE）
	for _, version := range clientInfo.SupportedVersions {
		if isGREASE(version) {
			continue
		}
		writeUint16(version)
	}
	_, _ = digest.Write([]byte{'|'})

	// 加密套件（过滤GREASE）
	for _, suite := range clientInfo.CipherSuites {
		if isGREASE(suite) {
			continue
		}
		writeUint16(suite)
	}
	_, _ = digest.Write([]byte{'|'})

	// 椭圆曲线（过滤GREASE）
	for _, curve := range clientInfo.SupportedCurves {
		if isGREASE(uint16(curve)) {
			continue
		}
		writeUint16(uint16(curve))
	}
	_, _ = digest.Write([]byte{'|'})

	// 点格式
	_, _ = digest.Write(clientInfo.SupportedPoints)
	_, _ = digest.Write([]byte{'|'})

	// 签名算法（过滤GREASE）
	for _, scheme := range clientInfo.SignatureSchemes {
		if isGREASE(uint16(scheme)) {
			continue
		}
		writeUint16(uint16(scheme))
	}
	_, _ = digest.Write([]byte{'|'})

	// ALPN协议
	for _, proto := range clientInfo.SupportedProtos {
		_, _ = digest.Write([]byte(proto))
		_, _ = digest.Write([]byte{','})
	}

	var sum = digest.Sum64()
	var result = make([]byte, 8)
	binary.BigEndian.PutUint64(result, sum)
	return result
}

// isGREASE 判断是否为GREASE占位值（RFC 8701）。
// GREASE值为 0x0a0a, 0x1a1a, ..., 0xfafa —— 高低字节相同且低半字节为0xa。
func isGREASE(v uint16) bool {
	var low = byte(v)
	return byte(v>>8) == low && (low&0x0f) == 0x0a
}
