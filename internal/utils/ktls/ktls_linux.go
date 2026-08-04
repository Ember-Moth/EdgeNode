// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build linux

package ktls

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// linux/tls.h 常量
const (
	solTLS = 282 // SOL_TLS

	cipherTypeAESGCM128        = 51 // TLS_CIPHER_AES_GCM_128
	cipherTypeAESGCM256        = 52 // TLS_CIPHER_AES_GCM_256
	cipherTypeCHACHA20POLY1305 = 54 // TLS_CIPHER_CHACHA20_POLY1305

	lenAESGCM128Key, lenAESGCM128IV, lenAESGCM128Salt = 16, 8, 4
	lenAESGCM256Key, lenAESGCM256IV, lenAESGCM256Salt = 32, 8, 4
	lenCHACHA20Key, lenCHACHA20IV, lenCHACHA20Salt    = 32, 12, 0
	lenRecSeq                                         = 8
)

// EnableULP 在 fd 上挂载 TLS ULP（Upper Layer Protocol）。
// 必须在握手完成后、注入密钥前调用一次。
func EnableULP(fd int) error {
	if err := unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_ULP, "tls"); err != nil {
		return fmt.Errorf("ktls: set TCP_ULP=tls: %w", err)
	}
	return nil
}

// Enable 为 fd 的指定方向注入会话密钥，启用内核 TLS 卸载。
// 调用前需先 EnableULP(fd)。TX 方向启用后，对该 fd 的 sendfile/write 将由内核加密。
func Enable(fd int, dir Direction, km *KeyMaterial) error {
	info, err := buildCryptoInfo(km)
	if err != nil {
		return err
	}
	if err := unix.SetsockoptString(fd, solTLS, int(dir), string(info)); err != nil {
		return fmt.Errorf("ktls: set SOL_TLS dir=%d: %w", dir, err)
	}
	return nil
}

// buildCryptoInfo 按 cipher 组装内核所需的 crypto_info 字节序列。
// 布局：version(u16 host order) | cipher_type(u16) | iv | key | salt | rec_seq
func buildCryptoInfo(km *KeyMaterial) ([]byte, error) {
	var cipherType uint16
	var keyLen, ivLen, saltLen int
	switch km.Cipher {
	case CipherAESGCM128:
		cipherType, keyLen, ivLen, saltLen = cipherTypeAESGCM128, lenAESGCM128Key, lenAESGCM128IV, lenAESGCM128Salt
	case CipherAESGCM256:
		cipherType, keyLen, ivLen, saltLen = cipherTypeAESGCM256, lenAESGCM256Key, lenAESGCM256IV, lenAESGCM256Salt
	case CipherCHACHA20POLY1305:
		cipherType, keyLen, ivLen, saltLen = cipherTypeCHACHA20POLY1305, lenCHACHA20Key, lenCHACHA20IV, lenCHACHA20Salt
	default:
		return nil, fmt.Errorf("ktls: unsupported cipher %d", km.Cipher)
	}

	if len(km.Key) != keyLen || len(km.IV) != ivLen || len(km.Salt) != saltLen || len(km.RecSeq) != lenRecSeq {
		return nil, fmt.Errorf("ktls: bad key material lengths (key=%d/%d iv=%d/%d salt=%d/%d seq=%d/%d)",
			len(km.Key), keyLen, len(km.IV), ivLen, len(km.Salt), saltLen, len(km.RecSeq), lenRecSeq)
	}

	var buf = make([]byte, 0, 4+ivLen+keyLen+saltLen+lenRecSeq)
	var head [4]byte
	// crypto_info 头部为主机字节序的两个 u16
	binary.NativeEndian.PutUint16(head[0:2], uint16(km.Version))
	binary.NativeEndian.PutUint16(head[2:4], cipherType)
	buf = append(buf, head[:]...)
	buf = append(buf, km.IV...)
	buf = append(buf, km.Key...)
	buf = append(buf, km.Salt...)
	buf = append(buf, km.RecSeq...)
	return buf, nil
}
