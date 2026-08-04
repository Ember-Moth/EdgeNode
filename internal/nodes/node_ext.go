// Copyright 2022 GoEdge goedge.cdn@gmail.com. All rights reserved.
//go:build !script
// +build !script

package nodes

import (
	"strings"

	"github.com/TeaOSLab/EdgeNode/internal/js"
	"github.com/TeaOSLab/EdgeNode/internal/remotelogs"
)

// reloadCommonScripts 从当前节点配置重新编译公共脚本，作为每次脚本执行的前置库
func (this *Node) reloadCommonScripts() error {
	if sharedNodeConfig == nil {
		setCommonScripts(nil)
		return nil
	}

	var scripts []*js.Script
	for _, commonScript := range sharedNodeConfig.CommonScripts {
		if commonScript == nil || !commonScript.IsOn {
			continue
		}
		var code = strings.TrimSpace(commonScript.Code)
		if len(code) == 0 {
			continue
		}
		script, err := js.SharedEngine.Compile(code)
		if err != nil {
			remotelogs.Error("NODE", "compile common script '"+commonScript.Filename+"' failed: "+err.Error())
			continue
		}
		scripts = append(scripts, script)
	}
	setCommonScripts(scripts)
	return nil
}

func (this *Node) reloadIPLibrary() {

}

func (this *Node) notifyPlusChange() error {
	return nil
}

func (this *Node) execTOAChangedTask() error {
	return nil
}
