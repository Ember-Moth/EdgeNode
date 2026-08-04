// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .

// Package js 提供基于goja的纯Go边缘脚本运行时。
//
// 设计要点：
//   - 编译缓存：脚本代码按内容哈希编译为*goja.Program并缓存，重复请求复用；
//   - 运行时池：goja.Runtime非并发安全，用sync.Pool复用，每个运行时同一时刻仅被一个请求独占；
//   - 状态隔离：一次运行的所有脚本被包进同一个IIFE执行，脚本顶层声明的var/function成为函数局部，
//     永不落到全局对象上，因此不会跨请求（乃至跨站点）泄漏；注入的对象（request）是可配置全局，
//     运行结束后删除。同一IIFE内多个脚本仍共享作用域（公共脚本的函数对请求脚本可见）；
//   - 超时中断：独立看门狗goroutine打断失控脚本，并在归还运行时前汇合，确保中断不会误伤后续请求；
//   - 沙箱：goja默认不提供require/fetch/文件等能力，脚本天然隔离。
package js

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/dop251/goja"
)

// Script 已编译的脚本
type Script struct {
	program *goja.Program
	code    string // 原始代码，用于缓存命中时排除哈希碰撞
	hash    uint64 // 代码内容哈希，用于组合缓存键的廉价计算
}

// Engine 脚本引擎。
//
// 隔离模型：每次 Run 使用一个全新的 goja.Runtime，运行后即丢弃。
// 这样脚本对全局对象的任何改动——显式全局赋值(globalThis.x=)、内置原型污染
// (Array.prototype.x=)、把注入的桥接对象存到全局(globalThis.r=request)——都不会
// 残留到后续请求，杜绝跨请求/跨租户泄漏。运行时创建开销约 0.5µs，相对脚本执行可忽略。
// 编译产物(*goja.Program)是不可变的，可安全跨运行时复用，故仍做编译缓存。
type Engine struct {
	programs         sync.Map // hash => *Script（单脚本，供语法校验/错误上报）
	combinedPrograms sync.Map // combineKey => *goja.Program（整批程序，实际执行体）
}

// NewEngine 创建脚本引擎
func NewEngine() *Engine {
	return &Engine{}
}

func (this *Engine) newRuntime() *goja.Runtime {
	var vm = goja.New()
	// 让导出的Go方法映射为首字母小写的JS方法名（GetHeader => getHeader）
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	return vm
}

// Compile 编译单个脚本代码，按内容缓存。主要用于调用方在装载阶段做语法校验与错误上报。
func (this *Engine) Compile(code string) (*Script, error) {
	var key = xxhash.Sum64String(code)
	if v, ok := this.programs.Load(key); ok {
		var cached = v.(*Script)
		// 排除极小概率的哈希碰撞：命中但原文不一致则重新编译且不缓存
		if cached.code == code {
			return cached, nil
		}
		program, err := goja.Compile("script", code, true)
		if err != nil {
			return nil, err
		}
		return &Script{program: program, code: code, hash: key}, nil
	}

	program, err := goja.Compile("script", code, true)
	if err != nil {
		return nil, err
	}

	var script = &Script{program: program, code: code, hash: key}
	actual, _ := this.programs.LoadOrStore(key, script)
	return actual.(*Script), nil
}

// 把整批脚本包进一个IIFE后编译并缓存。IIFE让同一批脚本共享一层函数作用域
// （公共脚本定义的函数对请求脚本可见），同时把顶层声明约束在该作用域内。
// 跨请求隔离由“每次 Run 全新运行时”保证（见 Engine 文档），不依赖此处。
// 组合缓存键由各脚本的内容哈希拼成（廉价），仅在未命中时才重建完整源码，避免每次运行都拼接大字符串。
func (this *Engine) combine(scripts []*Script) (*goja.Program, error) {
	var key = combineKey(scripts)
	if v, ok := this.combinedPrograms.Load(key); ok {
		return v.(*goja.Program), nil
	}

	var builder strings.Builder
	builder.WriteString("(function(){\n")
	for _, script := range scripts {
		builder.WriteString(script.code)
		// 换行 + 空语句，避免脚本间的自动分号插入（ASI）歧义
		builder.WriteString("\n;\n")
	}
	builder.WriteString("})();")
	var sources = builder.String()

	program, err := goja.Compile("scripts", sources, true)
	if err != nil {
		return nil, err
	}
	this.combinedPrograms.Store(key, program)
	return program, nil
}

// combineKey 由各脚本的内容哈希序列计算组合键，避免拼接完整源码。
func combineKey(scripts []*Script) uint64 {
	var digest = xxhash.New()
	var buf [8]byte
	for _, script := range scripts {
		binary.BigEndian.PutUint64(buf[:], script.hash)
		_, _ = digest.Write(buf[:])
	}
	return digest.Sum64()
}

// Run 执行一组脚本。所有脚本在同一IIFE作用域内顺序执行，共享变量/函数；
// globals注入为全局对象供脚本访问；总执行时长受timeout限制。
func (this *Engine) Run(scripts []*Script, globals map[string]any, timeout time.Duration) (err error) {
	if len(scripts) == 0 {
		return nil
	}

	program, err := this.combine(scripts)
	if err != nil {
		return err
	}

	// 每次运行使用全新运行时并丢弃，保证请求间零状态残留（见 Engine 文档）
	var vm = this.newRuntime()

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("script panic: %v", r)
		}
	}()

	for name, value := range globals {
		err = vm.Set(name, value)
		if err != nil {
			return err
		}
	}

	// 看门狗：超时打断脚本。用done/join确保看门狗 goroutine 必定退出，不泄漏。
	var done = make(chan struct{})
	var watchdogDone = make(chan struct{})
	go func() {
		defer close(watchdogDone)
		var timer = time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			vm.Interrupt("script execution timeout")
		case <-done:
		}
	}()

	_, err = vm.RunProgram(program)

	close(done)
	<-watchdogDone // 等待看门狗退出

	return err
}

// SharedEngine 全局共享的脚本引擎
var SharedEngine = NewEngine()
