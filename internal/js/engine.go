// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .

// Package js 提供基于goja的纯Go边缘脚本运行时。
//
// 设计要点：
//   - 编译缓存：脚本代码按内容哈希编译为*goja.Program并缓存，重复请求复用；
//   - 运行时池：goja.Runtime非并发安全，用sync.Pool复用，每个运行时同一时刻仅被一个请求独占；
//   - 超时中断：通过Interrupt在独立goroutine中打断失控脚本；
//   - 沙箱：goja默认不提供require/fetch/文件等能力，脚本天然隔离；
//   - 全局清理：每次运行结束删除注入的全局对象，避免池化运行时持有已结束请求的引用。
package js

import (
	"fmt"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/dop251/goja"
)

// Script 已编译的脚本
type Script struct {
	program *goja.Program
}

// Engine 脚本引擎
type Engine struct {
	programs sync.Map // hash => *Script
	pool     sync.Pool
}

// NewEngine 创建脚本引擎
func NewEngine() *Engine {
	var engine = &Engine{}
	engine.pool.New = func() any {
		return engine.newRuntime()
	}
	return engine
}

func (this *Engine) newRuntime() *goja.Runtime {
	var vm = goja.New()
	// 让导出的Go方法映射为首字母小写的JS方法名（GetHeader => getHeader）
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	return vm
}

// Compile 编译脚本代码，按内容缓存
func (this *Engine) Compile(code string) (*Script, error) {
	var key = xxhash.Sum64String(code)
	if v, ok := this.programs.Load(key); ok {
		return v.(*Script), nil
	}

	program, err := goja.Compile("script", code, true)
	if err != nil {
		return nil, err
	}

	var script = &Script{program: program}
	actual, _ := this.programs.LoadOrStore(key, script)
	return actual.(*Script), nil
}

// Run 顺序执行一组脚本，注入globals为全局对象，并限制总执行时长。
// 脚本运行在共享作用域内，前面的脚本（如公共脚本）定义的函数/变量对后面的脚本可见。
func (this *Engine) Run(scripts []*Script, globals map[string]any, timeout time.Duration) (err error) {
	if len(scripts) == 0 {
		return nil
	}

	var vm = this.pool.Get().(*goja.Runtime)

	// reusable 标记运行结束后运行时是否可安全归还池中；
	// 一旦发生panic或被中断，运行时状态不可预期，直接丢弃。
	var reusable = false

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("script panic: %v", r)
		}

		// 清除注入的全局对象，避免持有已结束请求的引用
		var globalObject = vm.GlobalObject()
		for name := range globals {
			_ = globalObject.Delete(name)
		}

		if reusable {
			vm.ClearInterrupt()
			this.pool.Put(vm)
		}
	}()

	for name, value := range globals {
		err = vm.Set(name, value)
		if err != nil {
			return err
		}
	}

	// 超时看门狗
	var timer = time.AfterFunc(timeout, func() {
		vm.Interrupt("script execution timeout")
	})
	defer timer.Stop()

	for _, script := range scripts {
		_, err = vm.RunProgram(script.program)
		if err != nil {
			return err
		}
	}

	reusable = true
	return nil
}

// SharedEngine 全局共享的脚本引擎
var SharedEngine = NewEngine()
