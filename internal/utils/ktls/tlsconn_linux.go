// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build linux

// 本文件通过 unsafe 镜像 crypto/tls 的私有结构，提取 TLS 会话密钥物料以配置内核 kTLS。
//
// 重要：这依赖 Go 标准库 crypto/tls 的私有内存布局（Conn/halfConn 字段顺序与类型），
// 属于版本锁定的脆弱手法——每次升级 Go 都必须重新核对布局，否则会读到错误内存。
// 已用 KeyLogWriter 基准做自检测试（tlsconn_linux_test.go）验证当前 Go 版本下偏移正确。
// 该手法为独立实现（BSD-3），仅在概念上参考了公开资料，未拷贝任何 GPL 代码。
//
// 布局对齐说明：切片头恒为 24 字节、接口恒为 16 字节、指针/函数为 8 字节，
// 因此对私有元素类型的切片/接口/指针，用同尺寸同对齐的替身（[]byte / any / unsafe.Pointer）即可保证偏移一致。

package ktls

import (
	"crypto/tls"
	"sync"
	"sync/atomic"
	"unsafe"
)

// mirrorHalfConn 复刻 crypto/tls.halfConn 的内存布局
type mirrorHalfConn struct {
	_             sync.Mutex
	err           any // error
	version       uint16
	cipher        any // any
	mac           any // hash.Hash
	seq           [8]byte
	scratchBuf    [13]byte
	nextCipher    any // any
	nextMac       any // hash.Hash
	level         int // QUICEncryptionLevel
	trafficSecret []byte
}

// mirrorConn 复刻 crypto/tls.Conn 的内存布局（仅需精确到 in/out 字段）
type mirrorConn struct {
	_                   any            // conn net.Conn
	isClient            bool           //nolint
	_                   unsafe.Pointer // handshakeFn func
	_                   unsafe.Pointer // quic *quicState
	isHandshakeComplete atomic.Bool
	_                   sync.Mutex // handshakeMutex
	_                   any        // handshakeErr error
	vers                uint16
	_                   bool           // haveVers
	_                   unsafe.Pointer // config *Config
	_                   int            // handshakes
	_                   bool           // extMasterSecret
	_                   bool           // didResume
	_                   bool           // didHRR
	cipherSuite         uint16
	_                   uint16         // curveID
	_                   uint16         // peerSigAlg
	_                   []byte         // ocspResponse
	_                   []byte         // scts [][]byte
	_                   []byte         // peerCertificates
	_                   []byte         // verifiedChains
	_                   string         // serverName
	_                   bool           // secureRenegotiation
	_                   unsafe.Pointer // ekm func
	_                   []byte         // resumptionSecret
	_                   bool           // echAccepted
	_                   []byte         // ticketKeys
	_                   bool           // clientFinishedIsFirst
	_                   any            // closeNotifyErr error
	_                   bool           // closeNotifySent
	_                   [12]byte       // clientFinished
	_                   [12]byte       // serverFinished
	_                   string         // clientProtocol
	in                  mirrorHalfConn
	out                 mirrorHalfConn
	// 其余字段无需复刻
}

// tlsConnState 从 *tls.Conn 提取的会话状态
type tlsConnState struct {
	isClient    bool
	version     uint16
	cipherSuite uint16
	// out：本端发送方向（服务端即 server->client）
	outTrafficSecret []byte
	outSeq           [8]byte
	// in：本端接收方向
	inTrafficSecret []byte
	inSeq           [8]byte
}

// extractTLSState 通过 unsafe 镜像读取 *tls.Conn 的私有会话状态
func extractTLSState(conn *tls.Conn) *tlsConnState {
	var m = (*mirrorConn)(unsafe.Pointer(conn))
	var state = &tlsConnState{
		isClient:         m.isClient,
		version:          m.vers,
		cipherSuite:      m.cipherSuite,
		outTrafficSecret: m.out.trafficSecret,
		outSeq:           m.out.seq,
		inTrafficSecret:  m.in.trafficSecret,
		inSeq:            m.in.seq,
	}
	return state
}
