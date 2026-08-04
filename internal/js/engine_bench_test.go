// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .

package js_test

import (
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeNode/internal/js"
)

// 典型的请求脚本：读取信息、设置变量、条件判断
const benchScriptCode = `
	var name = ctx.get();
	if (name.length > 0) {
		ctx.set("hi " + name);
	}
`

func BenchmarkEngine_Run(b *testing.B) {
	var engine = js.NewEngine()
	script, err := engine.Compile(benchScriptCode)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var bridge = &testBridge{value: "edge"}
		_ = engine.Run([]*js.Script{script}, map[string]any{"ctx": bridge}, time.Second)
	}
}

// 并发场景（模拟多请求同时执行脚本，考察运行时池复用）
func BenchmarkEngine_RunParallel(b *testing.B) {
	var engine = js.NewEngine()
	script, err := engine.Compile(benchScriptCode)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var bridge = &testBridge{value: "edge"}
			_ = engine.Run([]*js.Script{script}, map[string]any{"ctx": bridge}, time.Second)
		}
	})
}

// 编译缓存命中开销
func BenchmarkEngine_CompileCached(b *testing.B) {
	var engine = js.NewEngine()
	_, _ = engine.Compile(benchScriptCode)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Compile(benchScriptCode)
	}
}
