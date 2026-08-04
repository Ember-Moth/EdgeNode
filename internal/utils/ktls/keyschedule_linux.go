// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build linux && ktls

package ktls

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// TLS 1.3 套件（与 crypto/tls 常量一致）
const (
	tlsAES128GCMSHA256        = 0x1301
	tlsAES256GCMSHA384        = 0x1302
	tlsCHACHA20POLY1305SHA256 = 0x1303
)

// expandLabel 实现 TLS 1.3 的 HKDF-Expand-Label（RFC 8446 §7.1）
func expandLabel(newHash func() hash.Hash, secret []byte, label string, length int) ([]byte, error) {
	var fullLabel = "tls13 " + label
	// struct { uint16 length; opaque label<7..255>; opaque context<0..255> }
	var info = make([]byte, 0, 2+1+len(fullLabel)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, 0) // 空 context
	return hkdf.Expand(newHash, secret, string(info), length)
}

// deriveKeyMaterial 从 TLS 1.3 traffic secret 导出内核 kTLS 所需的密钥物料
func deriveKeyMaterial(cipherSuite uint16, trafficSecret []byte, seq [8]byte) (*KeyMaterial, error) {
	var newHash func() hash.Hash
	var cipher Cipher
	var keyLen int
	const ivLen = 12 // TLS 1.3 所有 AEAD 的 iv 均为 12 字节

	switch cipherSuite {
	case tlsAES128GCMSHA256:
		newHash, cipher, keyLen = sha256.New, CipherAESGCM128, 16
	case tlsAES256GCMSHA384:
		newHash, cipher, keyLen = sha512.New384, CipherAESGCM256, 32
	case tlsCHACHA20POLY1305SHA256:
		newHash, cipher, keyLen = sha256.New, CipherCHACHA20POLY1305, 32
	default:
		return nil, fmt.Errorf("ktls: unsupported TLS 1.3 cipher suite %#x", cipherSuite)
	}

	key, err := expandLabel(newHash, trafficSecret, "key", keyLen)
	if err != nil {
		return nil, err
	}
	iv, err := expandLabel(newHash, trafficSecret, "iv", ivLen)
	if err != nil {
		return nil, err
	}

	var recSeq = make([]byte, 8)
	copy(recSeq, seq[:])

	var km = &KeyMaterial{
		Version: VersionTLS13,
		Cipher:  cipher,
		Key:     key,
		RecSeq:  recSeq,
	}

	// 内核 crypto_info 的 salt/iv 拆分：
	//   AES-GCM：salt = iv[0:4]，iv = iv[4:12]（内核以 salt||iv 为固定 IV，按 TLS1.3 规则与 seq 异或）
	//   CHACHA20：salt 长度为 0，iv = 完整 12 字节
	if cipher == CipherCHACHA20POLY1305 {
		km.Salt = []byte{}
		km.IV = iv
	} else {
		km.Salt = iv[0:4]
		km.IV = iv[4:12]
	}

	return km, nil
}
