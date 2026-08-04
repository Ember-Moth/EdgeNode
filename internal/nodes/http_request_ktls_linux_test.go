// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build linux

package nodes

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	teaconst "github.com/TeaOSLab/EdgeNode/internal/const"
	"github.com/TeaOSLab/EdgeNode/internal/utils/ktls"
)

// 端到端验证 kTLS 零拷贝静态文件发送：真实 HTTPS(TLS1.3/HTTP1.1) 请求经 sendFileKTLS 输出，
// 客户端必须收到与磁盘文件字节完全一致的完整内容。
func TestSendFileKTLS_EndToEnd(t *testing.T) {
	if !ktls.Supported() {
		t.Skip("平台不支持 kTLS")
	}
	if err := ktls.SelfTest(); err != nil {
		t.Skipf("kTLS SelfTest 未通过（内核/布局不支持）：%v", err)
	}

	var oldFlag = teaconst.KTLSEnabled
	teaconst.KTLSEnabled = true
	defer func() { teaconst.KTLSEnabled = oldFlag }()

	// 构造一个 256KB、内容可校验的临时文件
	var content = bytes.Repeat([]byte("GoEdge-kTLS-zero-copy-payload-0123456789ABCDEF\n"), 6000)
	var fileSize = int64(len(content))
	var tmpFile = filepath.Join(t.TempDir(), "big.dat")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatal(err)
	}
	var wantSum = sha256.Sum256(content)

	// 真实 HTTPS 服务器；handler 走 sendFileKTLS
	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileReader, err := os.Open(tmpFile)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer func() { _ = fileReader.Close() }()

		var req = &HTTPRequest{
			RawReq:    r,
			RawWriter: w,
			ReqServer: &serverconfigs.ServerConfig{Id: 1},
			IsHTTPS:   true,
			web:       &serverconfigs.HTTPWebConfig{IsOn: true},
		}
		req.writer = NewHTTPWriter(req, w)
		req.writer.Header().Set("Content-Type", "application/octet-stream")

		if !req.canUseKTLSSendFile(fileSize, false) {
			t.Error("canUseKTLSSendFile 应为 true")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !req.sendFileKTLS(fileReader, 0, fileSize, http.StatusOK) {
			t.Error("sendFileKTLS 应返回 handled=true")
		}
	})

	var server = httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, // 强制 HTTP/1.1 以支持 Hijack
	}
	server.StartTLS()
	defer server.Close()

	var client = server.Client()
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.ForceAttemptHTTP2 = false
		transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}

	resp, err := client.Get(server.URL + "/big.dat")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if int64(len(body)) != fileSize {
		t.Fatalf("body 长度不符：got %d, want %d", len(body), fileSize)
	}
	var gotSum = sha256.Sum256(body)
	if gotSum != wantSum {
		t.Fatal("body 内容与源文件不一致（kTLS 加密/序列号错误?）")
	}
	if resp.ProtoMajor != 1 {
		t.Fatalf("期望 HTTP/1.1，实际 %s", resp.Proto)
	}

	t.Logf("✓ kTLS 零拷贝端到端成功：客户端完整正确收到 %d 字节 (proto=%s)", len(body), resp.Proto)
}

// 验证从文件非零偏移 sendfile（模拟缓存文件中 body 位于 meta+header 之后的 bodyOffset）
func TestSendFileKTLS_Offset(t *testing.T) {
	if !ktls.Supported() {
		t.Skip("平台不支持 kTLS")
	}
	if err := ktls.SelfTest(); err != nil {
		t.Skipf("kTLS SelfTest 未通过：%v", err)
	}

	var oldFlag = teaconst.KTLSEnabled
	teaconst.KTLSEnabled = true
	defer func() { teaconst.KTLSEnabled = oldFlag }()

	// 文件布局：[前缀垃圾][body]，只发送 body 部分
	var prefix = bytes.Repeat([]byte("METAHEADER-DO-NOT-SEND!"), 500) // 模拟 meta+header
	var body = bytes.Repeat([]byte("cached-body-content-0123456789\n"), 4000)
	var bodyOffset = int64(len(prefix))
	var bodySize = int64(len(body))

	var tmpFile = filepath.Join(t.TempDir(), "cache.dat")
	if err := os.WriteFile(tmpFile, append(append([]byte{}, prefix...), body...), 0644); err != nil {
		t.Fatal(err)
	}
	var wantSum = sha256.Sum256(body)

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp, err := os.Open(tmpFile)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer func() { _ = fp.Close() }()

		var req = &HTTPRequest{
			RawReq:    r,
			RawWriter: w,
			ReqServer: &serverconfigs.ServerConfig{Id: 1},
			IsHTTPS:   true,
			web:       &serverconfigs.HTTPWebConfig{IsOn: true},
		}
		req.writer = NewHTTPWriter(req, w)

		if !req.canUseKTLSCacheHit(bodySize) {
			t.Error("canUseKTLSCacheHit 应为 true")
			return
		}
		if !req.sendFileKTLS(fp, bodyOffset, bodySize, http.StatusOK) {
			t.Error("sendFileKTLS 应返回 handled=true")
		}
	})

	var server = httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()

	var client = server.Client()
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.ForceAttemptHTTP2 = false
		transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}

	resp, err := client.Get(server.URL + "/cache.dat")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(respBody)) != bodySize {
		t.Fatalf("长度不符：got %d want %d", len(respBody), bodySize)
	}
	if sha256.Sum256(respBody) != wantSum {
		t.Fatal("内容不符：应只发送 body 部分，不含前缀")
	}
	if bytes.Contains(respBody, []byte("METAHEADER")) {
		t.Fatal("响应中混入了偏移前的前缀数据")
	}

	t.Logf("✓ 偏移 sendfile 成功：仅发送 body %d 字节，未混入前缀", len(respBody))
}
