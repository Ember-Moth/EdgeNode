// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .

package js_test

import (
	"sync"
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeNode/internal/js"
)

// 供脚本调用的测试桥接
type testBridge struct {
	value string
}

func (this *testBridge) Set(v string) {
	this.value = v
}

func (this *testBridge) Get() string {
	return this.value
}

func TestEngine_RunBasic(t *testing.T) {
	var engine = js.NewEngine()

	script, err := engine.Compile(`ctx.set("hello " + ctx.get())`)
	if err != nil {
		t.Fatal(err)
	}

	var bridge = &testBridge{value: "world"}
	err = engine.Run([]*js.Script{script}, map[string]any{"ctx": bridge}, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if bridge.value != "hello world" {
		t.Fatal("unexpected value:", bridge.value)
	}
}

func TestEngine_CompileCache(t *testing.T) {
	var engine = js.NewEngine()

	const code = `ctx.set("x")`
	s1, err := engine.Compile(code)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := engine.Compile(code)
	if err != nil {
		t.Fatal(err)
	}
	if s1 != s2 {
		t.Fatal("same code should return cached script")
	}
}

func TestEngine_CompileError(t *testing.T) {
	var engine = js.NewEngine()
	_, err := engine.Compile(`function ( { syntax error`)
	if err == nil {
		t.Fatal("expected compile error")
	}
	t.Log("compile error as expected:", err)
}

func TestEngine_Timeout(t *testing.T) {
	var engine = js.NewEngine()

	// 死循环脚本
	script, err := engine.Compile(`while (true) {}`)
	if err != nil {
		t.Fatal(err)
	}

	var start = time.Now()
	err = engine.Run([]*js.Script{script}, nil, 100*time.Millisecond)
	var cost = time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if cost > 2*time.Second {
		t.Fatal("timeout did not fire in time, cost:", cost)
	}
	t.Log("interrupted after", cost, "err:", err)
}

func TestEngine_RuntimeError(t *testing.T) {
	var engine = js.NewEngine()

	// 引用未定义变量
	script, err := engine.Compile(`undefinedFunc()`)
	if err != nil {
		t.Fatal(err)
	}
	err = engine.Run([]*js.Script{script}, nil, time.Second)
	if err == nil {
		t.Fatal("expected runtime error")
	}
	t.Log("runtime error as expected:", err)
}

func TestEngine_SharedScope(t *testing.T) {
	var engine = js.NewEngine()

	// 前一个脚本定义的函数，后一个脚本可调用
	common, err := engine.Compile(`function greet(name) { return "hi " + name }`)
	if err != nil {
		t.Fatal(err)
	}
	main, err := engine.Compile(`ctx.set(greet("edge"))`)
	if err != nil {
		t.Fatal(err)
	}

	var bridge = &testBridge{}
	err = engine.Run([]*js.Script{common, main}, map[string]any{"ctx": bridge}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if bridge.value != "hi edge" {
		t.Fatal("unexpected value:", bridge.value)
	}
}

func TestEngine_Concurrent(t *testing.T) {
	var engine = js.NewEngine()
	script, err := engine.Compile(`ctx.set(ctx.get() + "!")`)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var bridge = &testBridge{value: "req"}
			runErr := engine.Run([]*js.Script{script}, map[string]any{"ctx": bridge}, time.Second)
			if runErr != nil {
				t.Error(runErr)
				return
			}
			if bridge.value != "req!" {
				t.Error("unexpected value:", bridge.value)
			}
		}(i)
	}
	wg.Wait()
}

// 脚本在顶层声明的全局变量/函数不应泄漏到下一次运行（跨请求/跨租户隔离）
func TestEngine_NoGlobalLeak(t *testing.T) {
	var engine = js.NewEngine()

	// 反复运行,验证任何形式的全局写入都不跨请求残留
	for i := 0; i < 20; i++ {
		// 租户A:声明顶层符号、显式写全局对象、污染内置原型、把桥接对象存到全局
		sA, err := engine.Compile(`
			var tenantSecret = "AAA";
			function helperA() { return 1 }
			globalThis.__leaked = "SECRET";
			Array.prototype.__poison = 42;
			globalThis.__savedCtx = (typeof ctx !== "undefined") ? ctx : null;
		`)
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.Run([]*js.Script{sA}, map[string]any{"ctx": &leakBridge{}}, time.Second); err != nil {
			t.Fatal(err)
		}

		// 租户B:尝试读取A的所有残留,应全部不可见
		var bridge = &leakBridge{}
		sB, err := engine.Compile(`
			ctx.report("var", typeof tenantSecret);
			ctx.report("func", typeof helperA);
			ctx.report("global", typeof globalThis.__leaked);
			ctx.report("proto", typeof [].__poison);
			ctx.report("savedCtx", typeof globalThis.__savedCtx);
		`)
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.Run([]*js.Script{sB}, map[string]any{"ctx": bridge}, time.Second); err != nil {
			t.Fatal(err)
		}

		for _, key := range []string{"var", "func", "global", "proto", "savedCtx"} {
			if bridge.report[key] != "undefined" {
				t.Fatalf("run %d: 泄漏[%s]=%q,应为 undefined", i, key, bridge.report[key])
			}
		}
	}
}

type leakBridge struct {
	report map[string]string
}

func (this *leakBridge) Report(key string, value string) {
	if this.report == nil {
		this.report = map[string]string{}
	}
	this.report[key] = value
}

// Compile 缓存命中时应比对原文，哈希碰撞不应返回错误脚本（此处验证正常缓存路径不被误伤）
func TestEngine_CompileCacheReturnsSameCode(t *testing.T) {
	var engine = js.NewEngine()
	const code = `var x = 1`
	s1, _ := engine.Compile(code)
	s2, _ := engine.Compile(code)
	if s1 != s2 {
		t.Fatal("identical code should hit cache and return the same *Script")
	}
}

// 运行结束后，池化运行时不应残留对上次globals的引用
func TestEngine_GlobalsCleared(t *testing.T) {
	var engine = js.NewEngine()

	// 第一次注入ctx
	s1, _ := engine.Compile(`ctx.set("a")`)
	var bridge = &testBridge{}
	if err := engine.Run([]*js.Script{s1}, map[string]any{"ctx": bridge}, time.Second); err != nil {
		t.Fatal(err)
	}

	// 第二次不注入ctx，引用ctx应报错（证明已清理，而非复用上次的）
	s2, _ := engine.Compile(`ctx.set("b")`)
	err := engine.Run([]*js.Script{s2}, nil, time.Second)
	if err == nil {
		t.Fatal("expected error: ctx should have been cleared from pooled runtime")
	}
	t.Log("globals cleared as expected:", err)
}
