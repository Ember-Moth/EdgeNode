// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"bytes"
	"crypto/tls"
	"testing"
)

func TestBaseListener_CalculateFingerprint(t *testing.T) {
	var listener = &BaseListener{}

	var hello1 = &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
	}

	var fp1 = listener.calculateFingerprint(hello1)
	if len(fp1) != 8 {
		t.Fatal("expected 8-byte fingerprint, got:", len(fp1))
	}

	// 相同ClientHello应产生相同指纹（稳定性）
	var fp1b = listener.calculateFingerprint(hello1)
	if !bytes.Equal(fp1, fp1b) {
		t.Fatal("fingerprint should be stable for identical ClientHello")
	}

	// 不同ClientHello应产生不同指纹（区分度）
	var hello2 = &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1301}, // 不同的加密套件
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
	}
	var fp2 = listener.calculateFingerprint(hello2)
	if bytes.Equal(fp1, fp2) {
		t.Fatal("different ClientHello should produce different fingerprint")
	}

	// nil输入返回nil
	if listener.calculateFingerprint(nil) != nil {
		t.Fatal("nil ClientHelloInfo should return nil")
	}

	t.Logf("fp1=%x fp2=%x", fp1, fp2)
}

// GREASE 值的差异不应改变指纹（同一客户端每次连接注入不同 GREASE，指纹须稳定）
func TestBaseListener_FingerprintIgnoresGREASE(t *testing.T) {
	var listener = &BaseListener{}

	var base = &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1301, 0x1302, 0xc02f},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedProtos:   []string{"h2"},
	}

	// 同一客户端的另一次连接：注入了不同的 GREASE 占位值
	var withGREASE = &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1a1a, 0x1301, 0x1302, 0xc02f}, // 前置一个 GREASE
		SupportedCurves:   []tls.CurveID{0x2a2a, tls.X25519, tls.CurveP256},
		SupportedVersions: []uint16{0x3a3a, tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedProtos:   []string{"h2"},
	}

	if !bytesEqual(listener.calculateFingerprint(base), listener.calculateFingerprint(withGREASE)) {
		t.Fatal("GREASE 值不应影响指纹")
	}
}

func TestIsGREASE(t *testing.T) {
	var greaseValues = []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x9a9a, 0xfafa}
	for _, v := range greaseValues {
		if !isGREASE(v) {
			t.Fatalf("%#x 应被识别为 GREASE", v)
		}
	}
	var normalValues = []uint16{0x1301, 0x1302, 0xc02f, 0x0000, 0x0a0b, 0x1b1b}
	for _, v := range normalValues {
		if isGREASE(v) {
			t.Fatalf("%#x 不应被识别为 GREASE", v)
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
