// Copyright 2023 GoEdge CDN goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"net/http"

	"github.com/TeaOSLab/EdgeNode/internal/stats"
	"github.com/iwind/TeaGo/types"
)

// 添加HTTP/3相关的响应报头
// 调用前提（见调用处）：IsHTTPS && !IsHTTP3 && ReqServer.SupportsHTTP3()
func (this *HTTPRequest) processHTTP3Headers(respHeader http.Header) {
	var nodeConfig = this.nodeConfig
	if nodeConfig == nil {
		return
	}

	var policy = nodeConfig.FindFirstEnabledHTTP3Policy()
	if policy == nil {
		return
	}

	// 部分移动端浏览器对HTTP/3支持不佳，默认不向其推送
	if !policy.SupportMobileBrowsers {
		var result = stats.SharedUserAgentParser.Parse(this.RawReq.UserAgent())
		if result.IsMobile {
			return
		}
	}

	// 不覆盖已有的Alt-Svc（可能来自源站）
	if len(respHeader.Get("Alt-Svc")) > 0 {
		return
	}

	respHeader.Set("Alt-Svc", `h3=":`+types.String(policy.Port)+`"; ma=2592000`)
}
