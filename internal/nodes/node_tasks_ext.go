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
	remotelogs.Println("NODE", "updating http cc policies ...")
	resp, err := rpcClient.NodeRPC.FindNodeHTTPCCPolicies(rpcClient.Context(), &pb.FindNodeHTTPCCPoliciesRequest{})
	if err != nil {
		return err
	}
	var policyMap = map[int64]*nodeconfigs.HTTPCCPolicy{}
	for _, policy := range resp.HttpCCPolicies {
		if len(policy.HttpCCPolicyJSON) == 0 {
			continue
		}
		var ccPolicy = nodeconfigs.NewHTTPCCPolicy()
		err = json.Unmarshal(policy.HttpCCPolicyJSON, ccPolicy)
		if err != nil {
			remotelogs.Error("NODE", "decode http cc policy failed: "+err.Error())
			continue
		}
		err = ccPolicy.Init()
		if err != nil {
			remotelogs.Error("NODE", "initialize http cc policy failed: "+err.Error())
			continue
		}
		policyMap[policy.NodeClusterId] = ccPolicy
	}

	if sharedNodeConfig == nil {
		return nil
	}
	sharedNodeConfig.UpdateHTTPCCPolicies(policyMap)
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
	remotelogs.Println("NODE", "updating http pages policies ...")
	resp, err := rpcClient.NodeRPC.FindNodeHTTPPagesPolicies(rpcClient.Context(), &pb.FindNodeHTTPPagesPoliciesRequest{})
	if err != nil {
		return err
	}
	var policyMap = map[int64]*nodeconfigs.HTTPPagesPolicy{}
	for _, policy := range resp.HttpPagesPolicies {
		if len(policy.HttpPagesPolicyJSON) == 0 {
			continue
		}
		var pagesPolicy = nodeconfigs.NewHTTPPagesPolicy()
		err = json.Unmarshal(policy.HttpPagesPolicyJSON, pagesPolicy)
		if err != nil {
			remotelogs.Error("NODE", "decode http pages policy failed: "+err.Error())
			continue
		}
		err = pagesPolicy.Init()
		if err != nil {
			remotelogs.Error("NODE", "initialize http pages policy failed: "+err.Error())
			continue
		}
		policyMap[policy.NodeClusterId] = pagesPolicy
	}

	if sharedNodeConfig == nil {
		return nil
	}
	sharedNodeConfig.UpdateHTTPPagesPolicies(policyMap)
	return nil
}

func (this *Node) execNetworkSecurityPolicyChangedTask(rpcClient *rpc.RPCClient) error {
	// stub
	return nil
}

func (this *Node) execPlanChangedTask(rpcClient *rpc.RPCClient) error {
	return nil
}
