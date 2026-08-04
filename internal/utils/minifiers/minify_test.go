// Copyright 2026 GoEdge CDN goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package minifiers

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
)

func newTestResponse(contentType string, body string) *http.Response {
	var header = http.Header{}
	header.Set("Content-Type", contentType)
	return &http.Response{
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMinifyResponse_HTML(t *testing.T) {
	var config = &serverconfigs.HTTPPageOptimizationConfig{
		HTML: &serverconfigs.HTTPHTMLOptimizationConfig{IsOn: true},
	}
	if err := config.Init(); err != nil {
		t.Fatal(err)
	}

	const raw = "<html>   <body>    <p>hello    world</p>   </body>  </html>"
	var resp = newTestResponse("text/html; charset=utf-8", raw)

	err := MinifyResponse(config, "https://example.com/", resp)
	if err != nil {
		t.Fatal(err)
	}

	var got = readBody(t, resp)
	if len(got) >= len(raw) {
		t.Fatal("html should be minified, got:", got)
	}
	if resp.ContentLength != int64(len(got)) {
		t.Fatal("content length mismatch:", resp.ContentLength, "vs", len(got))
	}
	t.Log("minified html:", got)
}

func TestMinifyResponse_CSS(t *testing.T) {
	var config = &serverconfigs.HTTPPageOptimizationConfig{
		CSS: &serverconfigs.HTTPCSSOptimizationConfig{IsOn: true},
	}
	if err := config.Init(); err != nil {
		t.Fatal(err)
	}

	const raw = "body {   color:  #ffffff;   margin: 0px;  }"
	var resp = newTestResponse("text/css", raw)

	err := MinifyResponse(config, "https://example.com/a.css", resp)
	if err != nil {
		t.Fatal(err)
	}

	var got = readBody(t, resp)
	if len(got) >= len(raw) {
		t.Fatal("css should be minified, got:", got)
	}
	t.Log("minified css:", got)
}

func TestMinifyResponse_JS(t *testing.T) {
	var config = &serverconfigs.HTTPPageOptimizationConfig{
		Javascript: &serverconfigs.HTTPJavascriptOptimizationConfig{IsOn: true},
	}
	if err := config.Init(); err != nil {
		t.Fatal(err)
	}

	const raw = "function  add( a , b )  {   return  a  +  b ;   }"
	var resp = newTestResponse("application/javascript", raw)

	err := MinifyResponse(config, "https://example.com/a.js", resp)
	if err != nil {
		t.Fatal(err)
	}

	var got = readBody(t, resp)
	if len(got) >= len(raw) {
		t.Fatal("js should be minified, got:", got)
	}
	t.Log("minified js:", got)
}

// 超过 8MB 上限的响应必须完整透传，不得被截断
func TestMinifyResponse_OverLimitNotTruncated(t *testing.T) {
	var config = &serverconfigs.HTTPPageOptimizationConfig{
		HTML: &serverconfigs.HTTPHTMLOptimizationConfig{IsOn: true},
	}
	if err := config.Init(); err != nil {
		t.Fatal(err)
	}

	// 构造 ~10MB 的 HTML(超过 8MB 上限)
	var raw = bytes.Repeat([]byte("<div>  padding content  </div>\n"), 350000)
	if len(raw) <= 8<<20 {
		t.Fatal("测试数据应超过 8MB")
	}

	// 模拟 chunked:ContentLength 未知(-1)
	var resp = &http.Response{
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(bytes.NewReader(raw)),
		ContentLength: -1,
	}

	if err := MinifyResponse(config, "https://example.com/", resp); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(raw) {
		t.Fatalf("响应被截断:got %d bytes, want %d(完整原文)", len(got), len(raw))
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("超限响应内容应与原文逐字节一致(未压缩、未截断)")
	}
	t.Logf("✓ 超限响应完整透传 %d 字节,未截断", len(got))
}

func TestMinifyResponse_Skip(t *testing.T) {
	var config = &serverconfigs.HTTPPageOptimizationConfig{
		HTML: &serverconfigs.HTTPHTMLOptimizationConfig{IsOn: true},
	}
	if err := config.Init(); err != nil {
		t.Fatal(err)
	}

	// 内容类型不匹配：不处理
	{
		const raw = "plain    text    content"
		var resp = newTestResponse("text/plain", raw)
		if err := MinifyResponse(config, "https://example.com/a.txt", resp); err != nil {
			t.Fatal(err)
		}
		if readBody(t, resp) != raw {
			t.Fatal("text/plain should not be modified")
		}
	}

	// 已压缩内容：不处理
	{
		const raw = "<html>  <body>x</body>  </html>"
		var resp = newTestResponse("text/html", raw)
		resp.Header.Set("Content-Encoding", "gzip")
		if err := MinifyResponse(config, "https://example.com/", resp); err != nil {
			t.Fatal(err)
		}
		if readBody(t, resp) != raw {
			t.Fatal("gzip-encoded content should not be modified")
		}
	}

	// 配置未启用：不处理
	{
		var offConfig = &serverconfigs.HTTPPageOptimizationConfig{
			HTML: &serverconfigs.HTTPHTMLOptimizationConfig{IsOn: false},
		}
		if err := offConfig.Init(); err != nil {
			t.Fatal(err)
		}
		const raw = "<html>  <body>x</body>  </html>"
		var resp = newTestResponse("text/html", raw)
		if err := MinifyResponse(offConfig, "https://example.com/", resp); err != nil {
			t.Fatal(err)
		}
		if readBody(t, resp) != raw {
			t.Fatal("disabled config should not modify content")
		}
	}
}
