// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build linux && ktls

package ktls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrNotTLS13 表示连接不是 TLS 1.3（kTLS 密钥提取当前仅支持 TLS 1.3）
var ErrNotTLS13 = errors.New("ktls: only TLS 1.3 is supported")

// Supported 报告本构建是否包含 kTLS 密钥提取能力（需以 -tags ktls 构建）
func Supported() bool { return true }

// SelfTest 在运行时验证 unsafe 结构体镜像与当前 Go 版本的 crypto/tls 布局一致。
//
// 做法：本地环回做一次 TLS 1.3 握手，同时用 KeyLogWriter 记录真实 traffic secret，
// 再用 unsafe 提取 out.trafficSecret 与之比对。一致则布局正确、可安全启用 kTLS；
// 不一致（例如升级 Go 后布局变动）返回错误，调用方应据此拒绝启用 kTLS 而非读错内存。
// 建议节点启动时调用一次，作为使用本包前的 fail-fast 断言。
func SelfTest() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	var tmpl = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ktls-selftest"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	var certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	var keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	var keyLog bytes.Buffer
	var keyLogMu sync.Mutex
	var serverConf = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: &lockedWriter{buf: &keyLog, mu: &keyLogMu},
	}
	var clientConf = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	var serverCh = make(chan *tls.Conn, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverCh <- nil
			return
		}
		tlsConn, _ := conn.(*tls.Conn)
		if tlsConn == nil || tlsConn.Handshake() != nil {
			serverCh <- nil
			return
		}
		_, _ = tlsConn.Write([]byte("x"))
		serverCh <- tlsConn
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), clientConf)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if err = client.Handshake(); err != nil {
		return err
	}
	var one [1]byte
	_, _ = client.Read(one[:])

	var server = <-serverCh
	if server == nil {
		return errors.New("ktls: selftest server handshake failed")
	}
	defer func() { _ = server.Close() }()

	var state = extractTLSState(server)
	if TLSVersion(state.version) != VersionTLS13 || state.isClient || len(state.outTrafficSecret) == 0 {
		return errors.New("ktls: selftest layout mismatch (version/isClient/secret) —— crypto/tls 布局可能已变动")
	}

	keyLogMu.Lock()
	var content = keyLog.String()
	keyLogMu.Unlock()
	var want = selfTestKeyLogSecret(content, "SERVER_TRAFFIC_SECRET_0")
	if want == nil {
		return errors.New("ktls: selftest keylog missing server secret")
	}
	if !bytes.Equal(state.outTrafficSecret, want) {
		return errors.New("ktls: selftest extracted secret mismatch —— unsafe 布局偏移错误，拒绝启用 kTLS")
	}
	return nil
}

func selfTestKeyLogSecret(log string, label string) []byte {
	for _, line := range strings.Split(log, "\n") {
		var fields = strings.Fields(line)
		if len(fields) == 3 && fields[0] == label {
			if secret, err := hex.DecodeString(fields[2]); err == nil {
				return secret
			}
		}
	}
	return nil
}

type lockedWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// EnableServerTX 在已完成握手的服务端 *tls.Conn 上启用内核 kTLS 发送方向卸载。
//
// 启用后，对返回的 fd 直接写入明文（或 sendfile）将由内核加密，实现零拷贝发送。
// 调用方在此之后必须停止通过 *tls.Conn 写数据，否则会与内核加密冲突导致流损坏。
//
// 前提：连接为 TLS 1.3 且握手已完成。密钥经 unsafe 从 crypto/tls 私有状态提取，
// 序列号取当前 out.seq（已计入握手后 Go 自动发送的 session ticket 等记录）。
func EnableServerTX(conn *tls.Conn) (fd int, err error) {
	var state = extractTLSState(conn)
	if TLSVersion(state.version) != VersionTLS13 {
		return -1, ErrNotTLS13
	}

	km, err := deriveKeyMaterial(state.cipherSuite, state.outTrafficSecret, state.outSeq)
	if err != nil {
		return -1, err
	}

	fd, err = rawConnFd(conn)
	if err != nil {
		return -1, err
	}

	if err = EnableULP(fd); err != nil {
		return -1, err
	}
	if err = Enable(fd, TX, km); err != nil {
		return -1, err
	}
	return fd, nil
}

// rawConnFd 通过公开的 NetConn() 取底层 TCP 的裸文件描述符（不依赖 unsafe）
func rawConnFd(conn *tls.Conn) (int, error) {
	var netConn = conn.NetConn()
	syscallConn, ok := netConn.(syscall.Conn)
	if !ok {
		return -1, errors.New("ktls: underlying conn is not a syscall.Conn")
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int = -1
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return fd, nil
}
