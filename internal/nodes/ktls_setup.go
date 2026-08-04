// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .

package nodes

import (
	"os"

	teaconst "github.com/TeaOSLab/EdgeNode/internal/const"
	"github.com/TeaOSLab/EdgeNode/internal/remotelogs"
	"github.com/TeaOSLab/EdgeNode/internal/utils/ktls"
)

// setupKTLS 在节点启动时决定是否启用内核 TLS 卸载。
//
// 由于 kTLS 依赖 unsafe 读取 crypto/tls 私有布局（版本锁定），这里以 SelfTest 做 fail-fast 门控：
// 仅当当前 Go 版本布局与镜像一致、且平台/内核支持时才启用。可用 EDGE_KTLS=0 强制关闭。
func (this *Node) setupKTLS() {
	if os.Getenv("EDGE_KTLS") == "0" {
		remotelogs.Println("NODE", "[KTLS]disabled by EDGE_KTLS=0")
		return
	}

	if !ktls.Supported() {
		remotelogs.Println("NODE", "[KTLS]not supported on this platform, skipped")
		return
	}

	if err := ktls.SelfTest(); err != nil {
		remotelogs.Warn("NODE", "[KTLS]self-test failed, kTLS disabled: "+err.Error())
		return
	}

	teaconst.KTLSEnabled = true
	remotelogs.Println("NODE", "[KTLS]enabled (kernel TLS offload for zero-copy sending)")
}
