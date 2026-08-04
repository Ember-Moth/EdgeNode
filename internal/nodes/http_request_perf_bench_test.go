// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus && !script

package nodes

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/nodeconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
)

// CC 计数热路径（阈值内放行，不触发封禁）
func BenchmarkDoCC(b *testing.B) {
	var ccConfig = &serverconfigs.HTTPCCConfig{
		IsOn: true,
		Thresholds: []*serverconfigs.HTTPCCThreshold{
			{Period: 60, MaxRequests: 1_000_000_000, BlockSeconds: 300},
		},
	}

	// 请求对象构造在循环外，隔离出 doCC 本身的开销
	var rawReq = httptest.NewRequest(http.MethodGet, "https://cctest.example.com/path", nil)
	rawReq.RemoteAddr = "203.0.113.10:12345"
	var recorder = httptest.NewRecorder()
	var req = &HTTPRequest{
		RawReq:     rawReq,
		RawWriter:  recorder,
		ReqServer:  &serverconfigs.ServerConfig{Id: 88001},
		ReqHost:    "cctest.example.com",
		IsHTTPS:    true,
		uri:        "/path",
		web:        &serverconfigs.HTTPWebConfig{IsOn: true, CC: ccConfig},
		nodeConfig: &nodeconfigs.NodeConfig{},
	}
	req.writer = NewHTTPWriter(req, recorder)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = req.doCC()
	}
}

// TLS 指纹计算
func BenchmarkCalculateFingerprint(b *testing.B) {
	var listener = &BaseListener{}
	var hello = &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256, tls.PKCS1WithSHA256},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = listener.calculateFingerprint(hello)
	}
}
