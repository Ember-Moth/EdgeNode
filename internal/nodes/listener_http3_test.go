// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeCommon/pkg/nodeconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs/sslconfigs"
	"github.com/iwind/TeaGo/types"
	"github.com/quic-go/quic-go/http3"
)

const testHTTP3Domain = "h3test.example.com"

func TestHTTP3Listener_EndToEnd(t *testing.T) {
	certPEM, keyPEM := generateHTTP3TestCert(t)

	// SSL策略
	var sslPolicy = &sslconfigs.SSLPolicy{
		IsOn:         true,
		HTTP3Enabled: true,
		Certs: []*sslconfigs.SSLCertConfig{
			{
				IsOn:     true,
				CertData: certPEM,
				KeyData:  keyPEM,
			},
		},
	}
	err := sslPolicy.Init(context.Background())
	if err != nil {
		t.Fatal("init ssl policy:", err)
	}

	// 服务配置
	var server = &serverconfigs.ServerConfig{
		Id:   1,
		IsOn: true,
		Type: serverconfigs.ServerTypeHTTPProxy,
		ServerNames: []*serverconfigs.ServerNameConfig{
			{Name: testHTTP3Domain},
		},
		Web: &serverconfigs.HTTPWebConfig{
			IsOn: true,
		},
		HTTPS: &serverconfigs.HTTPSProtocolConfig{
			BaseProtocol: serverconfigs.BaseProtocol{IsOn: true},
			SSLPolicy:    sslPolicy,
		},
	}
	errs := server.Init(context.Background())
	if len(errs) > 0 {
		t.Fatal("init server:", errs[0])
	}
	if !server.SupportsHTTP3() {
		t.Fatal("server should support http3")
	}

	var group = serverconfigs.NewServerAddressGroup("HTTP3")
	group.Add(server)

	var oldNodeConfig = sharedNodeConfig
	sharedNodeConfig = &nodeconfigs.NodeConfig{IsOn: true}
	defer func() {
		sharedNodeConfig = oldNodeConfig
	}()

	// 监听（端口0：系统自动分配）
	var listener = NewHTTP3Listener(group, 0)
	err = listener.Listen()
	if err != nil {
		t.Fatal("listen:", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	if listener.Port() <= 0 {
		t.Fatal("invalid listener port:", listener.Port())
	}

	// HTTP/3客户端
	var certPool = x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append cert to pool failed")
	}
	var transport = &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			ServerName: testHTTP3Domain,
		},
	}
	defer func() {
		_ = transport.Close()
	}()

	var client = &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+types.String(listener.Port())+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = testHTTP3Domain

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("do request:", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.ProtoMajor != 3 {
		t.Fatal("expected HTTP/3 response, got proto:", resp.Proto)
	}

	// 该服务没有配置源站和根目录，管线应完整走通并返回404
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal("expected status 404, got:", resp.StatusCode)
	}

	t.Log("proto:", resp.Proto, "status:", resp.StatusCode)
}

func TestHTTPRequest_ProcessHTTP3Headers(t *testing.T) {
	var nodeConfig = &nodeconfigs.NodeConfig{}
	nodeConfig.UpdateHTTP3Policies(map[int64]*nodeconfigs.HTTP3Policy{
		1: {IsOn: true, Port: 8443},
	})

	// Alt-Svc 现在要求该端口的 HTTP/3 监听器确实已启动:注入一个占位监听器
	var oldManager = sharedListenerManager
	sharedListenerManager = &ListenerManager{
		http3ListenersMap: map[int]*HTTP3Listener{8443: {}},
	}
	defer func() { sharedListenerManager = oldManager }()

	var newRequest = func(userAgent string) *HTTPRequest {
		rawReq, err := http.NewRequest(http.MethodGet, "https://"+testHTTP3Domain+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		rawReq.Header.Set("User-Agent", userAgent)
		return &HTTPRequest{
			RawReq:     rawReq,
			nodeConfig: nodeConfig,
		}
	}

	const desktopUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	const mobileUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"

	// 桌面端：推送Alt-Svc
	{
		var header = http.Header{}
		newRequest(desktopUA).processHTTP3Headers(header)
		if header.Get("Alt-Svc") != `h3=":8443"; ma=2592000` {
			t.Fatal("unexpected Alt-Svc:", header.Get("Alt-Svc"))
		}
	}

	// 移动端：默认不推送
	{
		var header = http.Header{}
		newRequest(mobileUA).processHTTP3Headers(header)
		if len(header.Get("Alt-Svc")) > 0 {
			t.Fatal("should not push Alt-Svc to mobile browsers, got:", header.Get("Alt-Svc"))
		}
	}

	// 开启SupportMobileBrowsers后：移动端也推送
	{
		nodeConfig.UpdateHTTP3Policies(map[int64]*nodeconfigs.HTTP3Policy{
			1: {IsOn: true, Port: 8443, SupportMobileBrowsers: true},
		})
		var header = http.Header{}
		newRequest(mobileUA).processHTTP3Headers(header)
		if header.Get("Alt-Svc") != `h3=":8443"; ma=2592000` {
			t.Fatal("unexpected Alt-Svc for mobile:", header.Get("Alt-Svc"))
		}
	}

	// 已有Alt-Svc时不覆盖
	{
		var header = http.Header{}
		header.Set("Alt-Svc", `h3=":443"; ma=86400`)
		newRequest(desktopUA).processHTTP3Headers(header)
		if header.Get("Alt-Svc") != `h3=":443"; ma=86400` {
			t.Fatal("should not overwrite existing Alt-Svc")
		}
	}

	// 策略未启用时不推送
	{
		nodeConfig.UpdateHTTP3Policies(map[int64]*nodeconfigs.HTTP3Policy{
			1: {IsOn: false, Port: 8443},
		})
		var header = http.Header{}
		newRequest(desktopUA).processHTTP3Headers(header)
		if len(header.Get("Alt-Svc")) > 0 {
			t.Fatal("should not push Alt-Svc when policy is off")
		}
	}
}

func generateHTTP3TestCert(t *testing.T) (certPEM []byte, keyPEM []byte) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var template = x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testHTTP3Domain},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{testHTTP3Domain},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return
}
