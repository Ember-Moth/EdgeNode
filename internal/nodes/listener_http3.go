// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package nodes

import (
	"errors"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	"github.com/TeaOSLab/EdgeNode/internal/events"
	"github.com/TeaOSLab/EdgeNode/internal/remotelogs"
	"github.com/TeaOSLab/EdgeNode/internal/utils/goman"
	"github.com/iwind/TeaGo/types"
	"github.com/quic-go/quic-go/http3"
)

// HTTP3Listener HTTP/3监听器
// 不通过Listener进入，由ListenerManager单独管理，因为HTTP/3使用独立的UDP端口，且服务分组来自HTTP3Group()
type HTTP3Listener struct {
	port         int
	httpListener *HTTPListener

	udpConn  *net.UDPConn
	h3Server *http3.Server

	countActiveRequests int64
}

func NewHTTP3Listener(group *serverconfigs.ServerAddressGroup, port int) *HTTP3Listener {
	var httpListener = &HTTPListener{
		BaseListener: BaseListener{Group: group},
	}
	httpListener.addr = ":" + types.String(port)
	httpListener.isHTTPS = true
	httpListener.isHTTP3 = true

	return &HTTP3Listener{
		port:         port,
		httpListener: httpListener,
	}
}

// Listen 绑定UDP端口并开始服务
func (this *HTTP3Listener) Listen() error {
	udpAddr, err := net.ResolveUDPAddr("udp", ":"+types.String(this.port))
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	this.udpConn = udpConn

	// 支持传入端口0（系统自动分配），用于测试
	if this.port == 0 {
		localAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
		if ok {
			this.port = localAddr.Port
			this.httpListener.addr = ":" + types.String(this.port)
		}
	}

	this.h3Server = &http3.Server{
		Port:        this.port,
		TLSConfig:   http3.ConfigureTLSConfig(this.httpListener.buildTLSConfig()),
		IdleTimeout: HTTPIdleTimeout,
		Handler: http.HandlerFunc(func(rawWriter http.ResponseWriter, rawReq *http.Request) {
			atomic.AddInt64(&this.countActiveRequests, 1)
			defer atomic.AddInt64(&this.countActiveRequests, -1)
			this.httpListener.ServeHTTP(rawWriter, rawReq)
		}),
	}

	events.OnKey(events.EventQuit, this, func() {
		remotelogs.Println("LISTENER", "quit http3 ':"+types.String(this.port)+"'")
		_ = this.Close()
	})

	goman.New(func() {
		err := this.h3Server.Serve(udpConn)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			remotelogs.Error("LISTENER", "http3 ':"+types.String(this.port)+"' serve failed: "+err.Error())
		}
	})

	return nil
}

// Port 获取实际监听的端口
func (this *HTTP3Listener) Port() int {
	return this.port
}

// Reload 重载服务分组
func (this *HTTP3Listener) Reload(group *serverconfigs.ServerAddressGroup) {
	this.httpListener.Reload(group)
}

// Close 关闭监听器
func (this *HTTP3Listener) Close() error {
	events.Remove(this)

	var err error
	if this.h3Server != nil {
		err = this.h3Server.Close()
	}
	if this.udpConn != nil {
		_ = this.udpConn.Close()
	}
	return err
}

// CountActiveConnections 获取当前活跃的连接数
// HTTP/3没有传统连接的概念，这里以进行中的请求数代替
func (this *HTTP3Listener) CountActiveConnections() int {
	return types.Int(atomic.LoadInt64(&this.countActiveRequests))
}
