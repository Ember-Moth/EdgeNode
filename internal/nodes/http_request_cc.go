// Copyright 2023 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"net/http"
	"time"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs/firewallconfigs"
	"github.com/TeaOSLab/EdgeNode/internal/utils"
	"github.com/TeaOSLab/EdgeNode/internal/utils/counters"
	"github.com/TeaOSLab/EdgeNode/internal/waf"
	"github.com/iwind/TeaGo/types"
)

// CC防护
// 调用前提（见调用处）：this.web.CC != nil && this.web.CC.IsOn
func (this *HTTPRequest) doCC() (block bool) {
	var ccConfig = this.web.CC

	var remoteIP = this.requestRemoteAddr(true)
	if len(remoteIP) == 0 || utils.IsLocalIP(remoteIP) {
		return
	}

	var serverId = this.ReqServer.Id

	// 检查是否已被临时封禁
	// WAF开启时也会在更早阶段检查，这里兜底WAF未开启的情况
	expiresAt, isBanned := waf.SharedIPBlackList.ContainsExpires(waf.IPTypeAll, firewallconfigs.FirewallScopeServer, serverId, remoteIP)
	if isBanned {
		this.blockCC(int(expiresAt - time.Now().Unix()))
		return true
	}

	// URL范围
	if !ccConfig.MatchURL(this.URL()) {
		return
	}

	// 阈值来源：网站配置 > 集群策略 > 默认值
	var thresholds = ccConfig.Thresholds
	if len(thresholds) == 0 && this.nodeConfig != nil {
		var policy = this.nodeConfig.FindFirstEnabledHTTPCCPolicy()
		if policy != nil {
			thresholds = policy.Thresholds
		}
	}
	if len(thresholds) == 0 {
		thresholds = serverconfigs.DefaultHTTPCCThresholds
	}

	var serverIdString = types.String(serverId)

	// 相同周期的阈值共享计数，防止重复累加
	var ipCounts = map[int]uint32{}  // period => count
	var urlCounts = map[int]uint32{} // period => count

	for _, threshold := range thresholds {
		if threshold == nil || threshold.Period <= 0 {
			continue
		}

		// 单IP请求数
		if threshold.MaxRequests > 0 {
			count, ok := ipCounts[threshold.Period]
			if !ok {
				count = counters.SharedCounter.IncreaseKey("CC@"+serverIdString+"@"+remoteIP+"@"+types.String(threshold.Period), threshold.Period)
				ipCounts[threshold.Period] = count
			}
			if int64(count) > int64(threshold.MaxRequests) {
				this.banCC(remoteIP, serverId, threshold.BlockSeconds)
				return true
			}
		}

		// 单IP+单URL请求数
		if threshold.MaxRequestsPerURL > 0 {
			count, ok := urlCounts[threshold.Period]
			if !ok {
				count = counters.SharedCounter.IncreaseKey("CCU@"+serverIdString+"@"+remoteIP+"@"+this.RawReq.URL.Path+"@"+types.String(threshold.Period), threshold.Period)
				urlCounts[threshold.Period] = count
			}
			if int64(count) > int64(threshold.MaxRequestsPerURL) {
				this.banCC(remoteIP, serverId, threshold.BlockSeconds)
				return true
			}
		}
	}

	return
}

// 封禁IP并拒绝当前请求
func (this *HTTPRequest) banCC(remoteIP string, serverId int64, blockSeconds int) {
	if blockSeconds > 0 {
		waf.SharedIPBlackList.RecordIP(
			waf.IPTypeAll,
			firewallconfigs.FirewallScopeServer,
			serverId,
			remoteIP,
			time.Now().Unix()+int64(blockSeconds),
			0,     // policyId
			false, // useLocalFirewall
			0,     // groupId
			0,     // setId
			"CC防护自动封禁")
	}
	this.blockCC(blockSeconds)
}

// 拒绝当前请求
func (this *HTTPRequest) blockCC(retryAfterSeconds int) {
	this.isAttack = true
	if retryAfterSeconds > 0 {
		this.writer.Header().Set("Retry-After", types.String(retryAfterSeconds))
	}
	this.writeCode(http.StatusTooManyRequests, "Too Many Requests", "请求过于频繁，请稍后重试")
}
