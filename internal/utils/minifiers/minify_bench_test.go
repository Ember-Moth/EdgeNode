// Copyright 2026 GoEdge CDN goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package minifiers

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
)

var benchHTML = strings.Repeat(`<div class="item">   <p>hello    world</p>   <!-- comment -->   </div>`+"\n", 200)

func BenchmarkMinifyResponse_HTML(b *testing.B) {
	var config = &serverconfigs.HTTPPageOptimizationConfig{
		HTML: &serverconfigs.HTTPHTMLOptimizationConfig{IsOn: true},
	}
	if err := config.Init(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var header = http.Header{}
		header.Set("Content-Type", "text/html")
		var resp = &http.Response{
			Header:        header,
			Body:          io.NopCloser(strings.NewReader(benchHTML)),
			ContentLength: int64(len(benchHTML)),
		}
		if err := MinifyResponse(config, "https://example.com/", resp); err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
	}
}

// 内容类型不匹配的快速跳过路径开销
func BenchmarkMinifyResponse_Skip(b *testing.B) {
	var config = &serverconfigs.HTTPPageOptimizationConfig{
		HTML: &serverconfigs.HTTPHTMLOptimizationConfig{IsOn: true},
	}
	if err := config.Init(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var header = http.Header{}
		header.Set("Content-Type", "image/png")
		var resp = &http.Response{
			Header: header,
			Body:   io.NopCloser(strings.NewReader("binary")),
		}
		_ = MinifyResponse(config, "https://example.com/a.png", resp)
	}
}
