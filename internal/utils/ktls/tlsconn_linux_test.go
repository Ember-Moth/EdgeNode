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
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

func genTestCert(t *testing.T) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ktls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// 用 KeyLogWriter 记录的真实 traffic secret 作为基准，验证 unsafe 镜像提取到的
// out.trafficSecret 与之一致——从而证明结构体布局偏移在当前 Go 版本下正确。
func TestExtractTLSState_MatchesKeyLog(t *testing.T) {
	cert := genTestCert(t)

	var keyLog bytes.Buffer
	var keyLogMu sync.Mutex
	var syncedKeyLog = &syncWriter{buf: &keyLog, mu: &keyLogMu}

	serverConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: syncedKeyLog,
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

	var serverConnCh = make(chan *tls.Conn, 1)
	go func() {
		rawConn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverConnCh <- nil
			return
		}
		tlsConn := rawConn.(*tls.Conn)
		if hsErr := tlsConn.Handshake(); hsErr != nil {
			serverConnCh <- nil
			return
		}
		// 触发 session ticket 等握手后消息的发送
		_, _ = tlsConn.Write([]byte("x"))
		serverConnCh <- tlsConn
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), clientConf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	// 读掉服务端写的一个字节，确保握手后流程完成
	var oneByte [1]byte
	_, _ = client.Read(oneByte[:])

	server := <-serverConnCh
	if server == nil {
		t.Fatal("server handshake failed")
	}
	defer func() { _ = server.Close() }()

	// 提取服务端状态
	state := extractTLSState(server)

	if state.version != tls.VersionTLS13 {
		t.Fatalf("extracted version = %#x, want TLS1.3(0x0304) —— 镜像布局可能错位", state.version)
	}
	if state.isClient {
		t.Fatal("server side extracted isClient=true —— 布局错位")
	}
	if len(state.outTrafficSecret) == 0 {
		t.Fatal("extracted empty out trafficSecret —— 布局错位")
	}

	// 基准：从 keylog 取 SERVER_TRAFFIC_SECRET_0
	keyLogMu.Lock()
	logContent := keyLog.String()
	keyLogMu.Unlock()
	wantSecret := findKeyLogSecret(logContent, "SERVER_TRAFFIC_SECRET_0")
	if wantSecret == nil {
		t.Fatal("keylog 未记录 SERVER_TRAFFIC_SECRET_0")
	}

	if !bytes.Equal(state.outTrafficSecret, wantSecret) {
		t.Fatalf("unsafe 提取的 out.trafficSecret 与 keylog 基准不一致：\n  got  %x\n  want %x\n  —— 结构体镜像偏移错误",
			state.outTrafficSecret, wantSecret)
	}

	t.Logf("✓ 镜像布局正确：提取的 server traffic secret 与 keylog 基准一致 (cipher=%#x, outSeq=%x)",
		state.cipherSuite, state.outSeq)
}

func findKeyLogSecret(log string, label string) []byte {
	for _, line := range strings.Split(log, "\n") {
		var fields = strings.Fields(line)
		if len(fields) == 3 && fields[0] == label {
			secret, err := hex.DecodeString(fields[2])
			if err == nil {
				return secret
			}
		}
	}
	return nil
}

type syncWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
