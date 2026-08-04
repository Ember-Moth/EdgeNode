// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build linux && ktls

package ktls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeNode/internal/utils/ktls"
	"golang.org/x/sys/unix"
)

func e2eCert(t *testing.T) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ktls-e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// 端到端验证：服务端用从 crypto/tls 提取的真实会话密钥启用内核 kTLS 发送卸载，
// 直接对裸 fd 写明文（内核加密），普通 Go TLS 客户端必须能正确解密。
// 这证明 unsafe 密钥提取 + HKDF 密钥调度 + kTLS setsockopt 整条链路正确。
func TestEnableServerTX_EndToEnd(t *testing.T) {
	cert := e2eCert(t)
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	clientConf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	const payload = "ZERO-COPY-VIA-KERNEL-TLS-1234567890"

	var errCh = make(chan error, 1)
	go func() {
		rawConn, acceptErr := ln.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer func() { _ = rawConn.Close() }()
		tlsConn := rawConn.(*tls.Conn)
		if hsErr := tlsConn.Handshake(); hsErr != nil {
			errCh <- hsErr
			return
		}

		// 启用内核 kTLS 发送卸载
		fd, txErr := ktls.EnableServerTX(tlsConn)
		if txErr != nil {
			errCh <- txErr
			return
		}

		// 关键：绕过 tls.Conn，直接向裸 fd 写明文——内核负责加密
		_, wErr := unix.Write(fd, []byte(payload))
		errCh <- wErr
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), clientConf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var buf = make([]byte, len(payload))
	n, readErr := client.Read(buf)
	if readErr != nil {
		if serverErr := <-errCh; serverErr != nil {
			t.Fatalf("server side error: %v", serverErr)
		}
		t.Fatalf("client read failed (内核加密与客户端期望不一致?): %v", readErr)
	}

	if serverErr := <-errCh; serverErr != nil {
		t.Fatalf("server write error: %v", serverErr)
	}

	if string(buf[:n]) != payload {
		t.Fatalf("payload mismatch:\n  got  %q\n  want %q", buf[:n], payload)
	}

	t.Logf("✓ 端到端成功：内核 kTLS 加密的明文被 Go TLS 客户端正确解密：%q", buf[:n])
}

// SelfTest 在当前 Go 版本下应通过（布局正确）
func TestSelfTest(t *testing.T) {
	if !ktls.Supported() {
		t.Skip("kTLS 未启用（需 -tags ktls）")
	}
	if err := ktls.SelfTest(); err != nil {
		t.Fatalf("SelfTest 失败（crypto/tls 布局可能已变动）：%v", err)
	}
	t.Log("✓ SelfTest 通过：unsafe 结构镜像与当前 Go 版本一致")
}
