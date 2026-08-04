// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/nodeconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs/shared"
)

func testNewCCRequest(serverId int64, remoteAddr string, path string, ccConfig *serverconfigs.HTTPCCConfig) (*HTTPRequest, *httptest.ResponseRecorder) {
	var rawReq = httptest.NewRequest(http.MethodGet, "https://cctest.example.com"+path, nil)
	rawReq.RemoteAddr = remoteAddr

	var recorder = httptest.NewRecorder()
	var req = &HTTPRequest{
		RawReq:    rawReq,
		RawWriter: recorder,
		ReqServer: &serverconfigs.ServerConfig{Id: serverId},
		ReqHost:   "cctest.example.com",
		IsHTTPS:   true,
		uri:       path,
		web: &serverconfigs.HTTPWebConfig{
			IsOn: true,
			CC:   ccConfig,
		},
		nodeConfig: &nodeconfigs.NodeConfig{},
	}
	req.writer = NewHTTPWriter(req, recorder)
	return req, recorder
}

// 伪造 X-Forwarded-For 为回环地址不得绕过 CC(裸连接为真实公网 IP)
func TestHTTPRequest_DoCC_SpoofedXFFNotBypassed(t *testing.T) {
	const serverId = 91009
	var ccConfig = &serverconfigs.HTTPCCConfig{
		IsOn: true,
		Thresholds: []*serverconfigs.HTTPCCThreshold{
			{Period: 60, MaxRequests: 1, BlockSeconds: 0},
		},
	}

	var newReq = func() (*HTTPRequest, *httptest.ResponseRecorder) {
		req, rec := testNewCCRequest(serverId, "203.0.113.77:5555", "/", ccConfig)
		req.RawReq.Header.Set("X-Forwarded-For", "127.0.0.1") // 伪造成回环
		return req, rec
	}

	// 第一次放行
	if req, _ := newReq(); req.doCC() {
		t.Fatal("first request should pass")
	}
	// 第二次应被拦截 —— 证明伪造的回环 XFF 未让 CC 跳过
	req, rec := newReq()
	if !req.doCC() {
		t.Fatal("spoofed X-Forwarded-For: 127.0.0.1 不应绕过 CC")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
}

func TestHTTPRequest_DoCC_MaxRequests(t *testing.T) {
	const serverId = 91001
	const remoteAddr = "203.0.113.10:12345"

	var ccConfig = &serverconfigs.HTTPCCConfig{
		IsOn: true,
		Thresholds: []*serverconfigs.HTTPCCThreshold{
			{Period: 60, MaxRequests: 3, BlockSeconds: 300},
		},
	}

	// 阈值内的请求放行
	for i := 0; i < 3; i++ {
		req, _ := testNewCCRequest(serverId, remoteAddr, "/", ccConfig)
		if req.doCC() {
			t.Fatal("request", i+1, "should not be blocked")
		}
	}

	// 超出阈值：封禁并返回429
	{
		req, recorder := testNewCCRequest(serverId, remoteAddr, "/", ccConfig)
		if !req.doCC() {
			t.Fatal("request over threshold should be blocked")
		}
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatal("expected status 429, got:", recorder.Code)
		}
		if recorder.Header().Get("Retry-After") != "300" {
			t.Fatal("expected Retry-After 300, got:", recorder.Header().Get("Retry-After"))
		}
		if !req.isAttack {
			t.Fatal("blocked request should be marked as attack")
		}
	}

	// 后续请求直接命中封禁名单
	{
		req, recorder := testNewCCRequest(serverId, remoteAddr, "/", ccConfig)
		if !req.doCC() {
			t.Fatal("banned IP should be blocked")
		}
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatal("expected status 429 for banned IP, got:", recorder.Code)
		}
	}

	// 其他IP不受影响
	{
		req, _ := testNewCCRequest(serverId, "203.0.113.11:12345", "/", ccConfig)
		if req.doCC() {
			t.Fatal("other IP should not be blocked")
		}
	}
}

func TestHTTPRequest_DoCC_LocalIP(t *testing.T) {
	const serverId = 91002

	var ccConfig = &serverconfigs.HTTPCCConfig{
		IsOn: true,
		Thresholds: []*serverconfigs.HTTPCCThreshold{
			{Period: 60, MaxRequests: 1, BlockSeconds: 300},
		},
	}

	// 本地IP不做CC检查
	for i := 0; i < 3; i++ {
		req, _ := testNewCCRequest(serverId, "127.0.0.1:12345", "/", ccConfig)
		if req.doCC() {
			t.Fatal("local ip should not be blocked")
		}
	}
}

func TestHTTPRequest_DoCC_MaxRequestsPerURL(t *testing.T) {
	const serverId = 91003
	const remoteAddr = "203.0.113.20:12345"

	var ccConfig = &serverconfigs.HTTPCCConfig{
		IsOn: true,
		Thresholds: []*serverconfigs.HTTPCCThreshold{
			{Period: 60, MaxRequestsPerURL: 2, BlockSeconds: 0},
		},
	}

	// 同一URL阈值内放行
	for i := 0; i < 2; i++ {
		req, _ := testNewCCRequest(serverId, remoteAddr, "/a", ccConfig)
		if req.doCC() {
			t.Fatal("request", i+1, "to /a should not be blocked")
		}
	}

	// 同一URL超出阈值：拒绝但不封禁（BlockSeconds为0）
	{
		req, recorder := testNewCCRequest(serverId, remoteAddr, "/a", ccConfig)
		if !req.doCC() {
			t.Fatal("request over per-url threshold should be blocked")
		}
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatal("expected status 429, got:", recorder.Code)
		}
	}

	// 其他URL不受影响
	{
		req, _ := testNewCCRequest(serverId, remoteAddr, "/b", ccConfig)
		if req.doCC() {
			t.Fatal("request to /b should not be blocked")
		}
	}
}

func TestHTTPRequest_DoCC_ExceptURL(t *testing.T) {
	const serverId = 91004
	const remoteAddr = "203.0.113.30:12345"

	var ccConfig = &serverconfigs.HTTPCCConfig{
		IsOn: true,
		Thresholds: []*serverconfigs.HTTPCCThreshold{
			{Period: 60, MaxRequests: 1, BlockSeconds: 0},
		},
		ExceptURLPatterns: []*shared.URLPattern{
			{Type: shared.URLPatternTypeWildcard, Pattern: "*/static/*"},
		},
	}
	err := ccConfig.Init()
	if err != nil {
		t.Fatal(err)
	}

	// 排除的URL不做CC检查
	for i := 0; i < 3; i++ {
		req, _ := testNewCCRequest(serverId, remoteAddr, "/static/logo.png", ccConfig)
		if req.doCC() {
			t.Fatal("excepted url should not be blocked")
		}
	}

	// 其他URL正常检查
	{
		req, _ := testNewCCRequest(serverId, remoteAddr, "/api", ccConfig)
		if req.doCC() {
			t.Fatal("first request to /api should not be blocked")
		}
	}
	{
		req, recorder := testNewCCRequest(serverId, remoteAddr, "/api", ccConfig)
		if !req.doCC() {
			t.Fatal("second request to /api should be blocked")
		}
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatal("expected status 429, got:", recorder.Code)
		}
	}
}
