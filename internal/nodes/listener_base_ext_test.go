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
