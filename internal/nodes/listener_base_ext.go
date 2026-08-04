// Copyright 2023 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"crypto/tls"
	"encoding/binary"

	"github.com/cespare/xxhash/v2"
)

// calculateFingerprint 依据TLS ClientHello计算客户端指纹
// 采用JA3风格：将客户端在握手中声明的能力（TLS版本、加密套件、扩展相关的曲线/点格式/ALPN/签名算法）
// 拼接后做xxhash，得到一个稳定的8字节指纹。同一类客户端（浏览器/爬虫/攻击工具）通常产生相同指纹，
// 供CC等模块在IP之外增加一个识别维度。
func (this *BaseListener) calculateFingerprint(clientInfo *tls.ClientHelloInfo) []byte {
	if clientInfo == nil {
		return nil
	}

	var digest = xxhash.New()
	var buf [2]byte

	// TLS支持的版本
	for _, version := range clientInfo.SupportedVersions {
		binary.BigEndian.PutUint16(buf[:], version)
		_, _ = digest.Write(buf[:])
	}
	_, _ = digest.Write([]byte{'|'})

	// 加密套件
	for _, suite := range clientInfo.CipherSuites {
		binary.BigEndian.PutUint16(buf[:], suite)
		_, _ = digest.Write(buf[:])
	}
	_, _ = digest.Write([]byte{'|'})

	// 椭圆曲线
	for _, curve := range clientInfo.SupportedCurves {
		binary.BigEndian.PutUint16(buf[:], uint16(curve))
		_, _ = digest.Write(buf[:])
	}
	_, _ = digest.Write([]byte{'|'})

	// 点格式
	_, _ = digest.Write(clientInfo.SupportedPoints)
	_, _ = digest.Write([]byte{'|'})

	// 签名算法
	for _, scheme := range clientInfo.SignatureSchemes {
		binary.BigEndian.PutUint16(buf[:], uint16(scheme))
		_, _ = digest.Write(buf[:])
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
