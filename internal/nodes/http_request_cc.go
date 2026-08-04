// Copyright 2023 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"encoding/binary"
	"net/http"
	"sync"
	"time"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs/firewallconfigs"
	"github.com/TeaOSLab/EdgeNode/internal/utils"
	"github.com/TeaOSLab/EdgeNode/internal/utils/counters"
	"github.com/TeaOSLab/EdgeNode/internal/waf"
	"github.com/cespare/xxhash/v2"
	"github.com/iwind/TeaGo/types"
)

// CC去重的最大周期数（栈上数组容量）
const ccMaxDedup = 8

// 复用xxhash.Digest，避免CC计数key的字符串拼接分配
var ccDigestPool = sync.Pool{
	New: func() any { return xxhash.New() },
}

func containsInt(values []int, value int) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// ccKeyHash 原地计算CC计数key的哈希，不拼接字符串、不产生临时对象。
// prefix区分IP维度("C")与IP+URL维度("U")，确保两类计数互不干扰。
func ccKeyHash(prefix byte, serverId int64, remoteIP string, path string, period int) uint64 {
	var digest = ccDigestPool.Get().(*xxhash.Digest)
	digest.Reset()

	var buf [8]byte
	_, _ = digest.Write([]byte{prefix})
	binary.BigEndian.PutUint64(buf[:], uint64(serverId))
	_, _ = digest.Write(buf[:])
	_, _ = digest.WriteString(remoteIP)
	if len(path) > 0 {
		_, _ = digest.WriteString(path)
	}
	binary.BigEndian.PutUint64(buf[:], uint64(period))
	_, _ = digest.Write(buf[:])

	var h = digest.Sum64()
	ccDigestPool.Put(digest)
	return h
}

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

	var path = this.RawReq.URL.Path

	// 相同周期的阈值只累加一次。用栈上定长数组去重（阈值通常≤3个），不产生堆分配。
	// 超过容量的极端配置不再去重（最坏仅重复计数，不影响安全性）。
	var countedIP [ccMaxDedup]int
	var countedURL [ccMaxDedup]int
	var nIP, nURL int

	for _, threshold := range thresholds {
		if threshold == nil || threshold.Period <= 0 {
			continue
		}

		// 单IP请求数
		if threshold.MaxRequests > 0 && !containsInt(countedIP[:nIP], threshold.Period) {
			if nIP < len(countedIP) {
				countedIP[nIP] = threshold.Period
				nIP++
			}
			var count = counters.SharedCounter.Increase(ccKeyHash('C', serverId, remoteIP, "", threshold.Period), threshold.Period)
			if int64(count) > int64(threshold.MaxRequests) {
				this.banCC(remoteIP, serverId, threshold.BlockSeconds)
				return true
			}
		}

		// 单IP+单URL请求数
		if threshold.MaxRequestsPerURL > 0 && !containsInt(countedURL[:nURL], threshold.Period) {
			if nURL < len(countedURL) {
				countedURL[nURL] = threshold.Period
				nURL++
			}
			var count = counters.SharedCounter.Increase(ccKeyHash('U', serverId, remoteIP, path, threshold.Period), threshold.Period)
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
