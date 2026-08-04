// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build linux

package ktls_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/TeaOSLab/EdgeNode/internal/utils/ktls"
)

func rawFd(t *testing.T, conn net.Conn) int {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("not a TCPConn")
	}
	sc, err := tcpConn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	err = sc.Control(func(f uintptr) { fd = int(f) })
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// 通过一对 TCP 连接验证内核 kTLS 往返：
// 服务端设 TX、客户端设 RX（同密钥），服务端写明文，内核加密，客户端内核解密得到明文。
func testRoundTrip(t *testing.T, km func() *ktls.KeyMaterial) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	var accepted = make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		accepted <- acceptResult{conn, acceptErr}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	var res = <-accepted
	if res.err != nil {
		t.Fatal(res.err)
	}
	var server = res.conn
	defer func() { _ = server.Close() }()

	var serverFd = rawFd(t, server)
	var clientFd = rawFd(t, client)

	if err := ktls.EnableULP(serverFd); err != nil {
		t.Skipf("kTLS ULP 不可用（内核未启用 CONFIG_TLS？）：%v", err)
	}
	if err := ktls.EnableULP(clientFd); err != nil {
		t.Skipf("kTLS ULP 不可用：%v", err)
	}

	// kTLS 的 cipher 支持依内核而定（例如部分内核只支持 AES-GCM，不支持 CHACHA20），
	// setsockopt 对不支持的 cipher 返回 ENOENT/EINVAL。此时跳过而非失败。
	if err := ktls.Enable(serverFd, ktls.TX, km()); err != nil {
		t.Skipf("内核不支持该 cipher 的 kTLS 卸载：%v", err)
	}
	if err := ktls.Enable(clientFd, ktls.RX, km()); err != nil {
		t.Skipf("内核不支持该 cipher 的 kTLS 卸载：%v", err)
	}

	var msg = []byte("hello-ktls-zero-copy-payload")
	if _, err := server.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	var buf = make([]byte, 128)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("payload mismatch: got %q want %q", buf[:n], msg)
	}
}

func TestKTLS_AESGCM128_RoundTrip(t *testing.T) {
	testRoundTrip(t, func() *ktls.KeyMaterial {
		return &ktls.KeyMaterial{
			Version: ktls.VersionTLS12,
			Cipher:  ktls.CipherAESGCM128,
			Key:     bytes.Repeat([]byte{0x01}, 16),
			IV:      bytes.Repeat([]byte{0x02}, 8),
			Salt:    bytes.Repeat([]byte{0x03}, 4),
			RecSeq:  make([]byte, 8),
		}
	})
}

func TestKTLS_AESGCM256_RoundTrip(t *testing.T) {
	testRoundTrip(t, func() *ktls.KeyMaterial {
		return &ktls.KeyMaterial{
			Version: ktls.VersionTLS12,
			Cipher:  ktls.CipherAESGCM256,
			Key:     bytes.Repeat([]byte{0x01}, 32),
			IV:      bytes.Repeat([]byte{0x02}, 8),
			Salt:    bytes.Repeat([]byte{0x03}, 4),
			RecSeq:  make([]byte, 8),
		}
	})
}

func TestKTLS_CHACHA20_RoundTrip(t *testing.T) {
	testRoundTrip(t, func() *ktls.KeyMaterial {
		return &ktls.KeyMaterial{
			Version: ktls.VersionTLS12,
			Cipher:  ktls.CipherCHACHA20POLY1305,
			Key:     bytes.Repeat([]byte{0x01}, 32),
			IV:      bytes.Repeat([]byte{0x02}, 12),
			Salt:    []byte{},
			RecSeq:  make([]byte, 8),
		}
	})
}

func TestKTLS_BadKeyMaterial(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	var fd = rawFd(t, client)
	if err := ktls.EnableULP(fd); err != nil {
		t.Skipf("kTLS ULP 不可用：%v", err)
	}

	// 密钥长度错误应被拒绝
	err = ktls.Enable(fd, ktls.TX, &ktls.KeyMaterial{
		Version: ktls.VersionTLS12,
		Cipher:  ktls.CipherAESGCM128,
		Key:     []byte{0x01}, // 长度不对
		IV:      bytes.Repeat([]byte{0x02}, 8),
		Salt:    bytes.Repeat([]byte{0x03}, 4),
		RecSeq:  make([]byte, 8),
	})
	if err == nil {
		t.Fatal("expected error for bad key length")
	}
	t.Log("rejected bad key material as expected:", err)
}
