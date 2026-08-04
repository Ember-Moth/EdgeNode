// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !script

package nodes

import (
	"sync/atomic"
	"time"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	"github.com/TeaOSLab/EdgeNode/internal/js"
	"github.com/TeaOSLab/EdgeNode/internal/remotelogs"
)

// 单个脚本组的执行时长上限，作为失控脚本的兜底熔断（正常脚本应在毫秒级完成）
const scriptTimeout = 200 * time.Millisecond

// 节点级公共脚本，作为每次执行的前置库脚本
var commonScriptsPtr atomic.Pointer[[]*js.Script]

func setCommonScripts(scripts []*js.Script) {
	commonScriptsPtr.Store(&scripts)
}

func sharedCommonScripts() []*js.Script {
	var ptr = commonScriptsPtr.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// scriptRequest 暴露给JS的request对象。
// 方法经goja的UncapFieldNameMapper映射为首字母小写（GetHeader => request.getHeader）。
type scriptRequest struct {
	req *HTTPRequest
}

// ---- 读取请求信息 ----

func (this *scriptRequest) Method() string { return this.req.RawReq.Method }

func (this *scriptRequest) Scheme() string {
	if this.req.IsHTTPS {
		return "https"
	}
	return "http"
}

func (this *scriptRequest) Host() string { return this.req.ReqHost }

func (this *scriptRequest) Uri() string { return this.req.uri }

func (this *scriptRequest) Path() string { return this.req.Path() }

func (this *scriptRequest) RemoteAddr() string { return this.req.requestRemoteAddr(true) }

func (this *scriptRequest) GetHeader(name string) string {
	return this.req.RawReq.Header.Get(name)
}

func (this *scriptRequest) GetArg(name string) string {
	return this.req.RawReq.URL.Query().Get(name)
}

func (this *scriptRequest) GetCookie(name string) string {
	cookie, err := this.req.RawReq.Cookie(name)
	if err != nil || cookie == nil {
		return ""
	}
	return cookie.Value
}

// ---- 修改请求（影响回源） ----

func (this *scriptRequest) SetHeader(name string, value string) {
	this.req.RawReq.Header.Set(name, value)
}

func (this *scriptRequest) DeleteHeader(name string) {
	this.req.RawReq.Header.Del(name)
}

func (this *scriptRequest) SetUri(uri string) {
	this.req.SetURI(uri)
}

// ---- 变量（可在${name}中引用） ----

func (this *scriptRequest) SetVariable(name string, value string) {
	if this.req.varMapping == nil {
		this.req.varMapping = map[string]string{}
	}
	this.req.varMapping[name] = value
}

func (this *scriptRequest) GetVariable(name string) string {
	if this.req.varMapping == nil {
		return ""
	}
	return this.req.varMapping[name]
}

// ---- 响应（调用后请求结束） ----

func (this *scriptRequest) SetResponseHeader(name string, value string) {
	this.req.writer.Header().Set(name, value)
}

func (this *scriptRequest) Send(status int, body string) {
	this.req.writer.Send(status, body)
}

func (this *scriptRequest) Redirect(status int, url string) {
	this.req.writer.Redirect(status, url)
}

func (this *HTTPRequest) runScriptGroup(group *serverconfigs.ScriptGroupConfig) {
	if group == nil || !group.IsOn || group.IsEmpty() {
		return
	}

	var scripts []*js.Script

	// 公共脚本前置
	scripts = append(scripts, sharedCommonScripts()...)

	for _, scriptConfig := range group.Scripts {
		if scriptConfig == nil || !scriptConfig.IsOn {
			continue
		}
		var code = scriptConfig.RealCode()
		if len(code) == 0 {
			code = scriptConfig.TrimCode()
		}
		if len(code) == 0 {
			continue
		}
		script, err := js.SharedEngine.Compile(code)
		if err != nil {
			remotelogs.ServerError(this.ReqServer.Id, "HTTP_SCRIPT", "compile script failed: "+err.Error(), "", nil)
			continue
		}
		scripts = append(scripts, script)
	}

	if len(scripts) == 0 {
		return
	}

	var bridge = &scriptRequest{req: this}
	err := js.SharedEngine.Run(scripts, map[string]any{"request": bridge}, scriptTimeout)
	if err != nil {
		remotelogs.ServerError(this.ReqServer.Id, "HTTP_SCRIPT", "run script failed: "+err.Error(), "", nil)
	}
}
