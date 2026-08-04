// Copyright 2023 GoEdge CDN goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"encoding/json"

	"github.com/TeaOSLab/EdgeCommon/pkg/nodeconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
	"github.com/TeaOSLab/EdgeNode/internal/remotelogs"
	"github.com/TeaOSLab/EdgeNode/internal/rpc"
)

func (this *Node) execScriptsChangedTask() error {
	// stub
	return nil
}

func (this *Node) execUAMPolicyChangedTask(rpcClient *rpc.RPCClient) error {
	// stub
	return nil
}

func (this *Node) execHTTPCCPolicyChangedTask(rpcClient *rpc.RPCClient) error {
	// stub
	return nil
}

func (this *Node) execHTTP3PolicyChangedTask(rpcClient *rpc.RPCClient) error {
	remotelogs.Println("NODE", "updating http3 policies ...")
	resp, err := rpcClient.NodeRPC.FindNodeHTTP3Policies(rpcClient.Context(), &pb.FindNodeHTTP3PoliciesRequest{})
	if err != nil {
		return err
	}
	var policyMap = map[int64]*nodeconfigs.HTTP3Policy{}
	for _, policy := range resp.Http3Policies {
		if len(policy.Http3PolicyJSON) == 0 {
			continue
		}
		var http3Policy = nodeconfigs.NewHTTP3Policy()
		err = json.Unmarshal(policy.Http3PolicyJSON, http3Policy)
		if err != nil {
			remotelogs.Error("NODE", "decode http3 policy failed: "+err.Error())
			continue
		}
		err = http3Policy.Init()
		if err != nil {
			remotelogs.Error("NODE", "initialize http3 policy failed: "+err.Error())
			continue
		}
		policyMap[policy.NodeClusterId] = http3Policy
	}

	if sharedNodeConfig == nil {
		return nil
	}
	sharedNodeConfig.UpdateHTTP3Policies(policyMap)

	// 重新应用监听器
	return sharedListenerManager.Start(sharedNodeConfig)
}

func (this *Node) execHTTPPagesPolicyChangedTask(rpcClient *rpc.RPCClient) error {
	// stub
	return nil
}

func (this *Node) execNetworkSecurityPolicyChangedTask(rpcClient *rpc.RPCClient) error {
	// stub
	return nil
}

func (this *Node) execPlanChangedTask(rpcClient *rpc.RPCClient) error {
	return nil
}
