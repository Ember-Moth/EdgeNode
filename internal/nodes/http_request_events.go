// Copyright 2021 GoEdge goedge.cdn@gmail.com. All rights reserved.
//go:build !script
// +build !script

package nodes

// onInit 在请求处理最开始执行InitGroup脚本
func (this *HTTPRequest) onInit() {
	if this.web == nil || this.web.RequestScripts == nil {
		return
	}
	this.runScriptGroup(this.web.RequestScripts.InitGroup)
}

// onRequest 在实际处理（缓存/回源/静态）前执行RequestGroup脚本
func (this *HTTPRequest) onRequest() {
	if this.web == nil || this.web.RequestScripts == nil {
		return
	}
	this.runScriptGroup(this.web.RequestScripts.RequestGroup)
}
