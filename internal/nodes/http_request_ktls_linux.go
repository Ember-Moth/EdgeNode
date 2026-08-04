// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build linux

package nodes

import (
	"crypto/tls"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	teaconst "github.com/TeaOSLab/EdgeNode/internal/const"
	"github.com/TeaOSLab/EdgeNode/internal/utils/ktls"
	"golang.org/x/sys/unix"
)

// kTLS 零拷贝路径的最小文件大小：低于此值时 hijack+setsockopt 的开销以及丢失 keep-alive 不划算
const kTLSMinFileSize = 64 << 10 // 64KB

// canUseKTLSSendFile 判断当前静态文件响应是否可走 kTLS 零拷贝路径。
// 约束（任一不满足则回退到常规写入链，保持 keep-alive 与全部变换/缓存/计费行为）：
//   - kTLS 已启用且为 HTTPS TLS1.3
//   - GET 且完整文件（无 Range）
//   - 文件足够大
//   - 无压缩/WebP 等响应体变换（sendfile 发送的是原始字节）
//   - 不需要边写边缓存（sendfile 无法同时 tee 到缓存）
func (this *HTTPRequest) canUseKTLSSendFile(fileSize int64, hasRanges bool) bool {
	if !teaconst.KTLSEnabled || !this.IsHTTPS {
		return false
	}
	if this.RawReq.TLS == nil || this.RawReq.TLS.Version != tls.VersionTLS13 {
		return false
	}
	if this.RawReq.Method != http.MethodGet || hasRanges || fileSize < kTLSMinFileSize {
		return false
	}
	if this.web != nil {
		if this.web.Compression != nil && this.web.Compression.IsOn {
			return false
		}
		if this.web.WebP != nil && this.web.WebP.IsOn {
			return false
		}
	}
	if this.cacheRef != nil {
		return false
	}
	return true
}

// sendFileKTLS 通过内核 TLS 卸载 + sendfile 零拷贝发送整个文件。
// 返回 true 表示已接管并完成响应（无论成功与否，调用方不应再写响应）。
func (this *HTTPRequest) sendFileKTLS(fileReader *os.File, fileSize int64) (handled bool) {
	// 接管连接（此后 net/http 不再管理该连接，我们负责写完整响应并关闭）
	conn, _, err := this.writer.Hijack()
	if err != nil || conn == nil {
		return false // 未接管，安全回退到常规路径
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return true
	}
	defer func() {
		_ = tlsConn.Close()
	}()

	var clientConn = clientConnOfTLS(tlsConn)
	var head = this.buildKTLSResponseHead(fileSize)

	_, err = ktls.EnableServerTX(tlsConn)
	if err != nil {
		// kTLS 启用失败（如非 TLS1.3 / 内核不支持）：退回用户态 TLS 写入，仍然正确，只是无零拷贝。
		// 经 tls.Conn.Write -> ClientConn.Write，计费照常。
		if _, wErr := tlsConn.Write(head); wErr == nil {
			_, _ = this.copyFileUserspace(tlsConn, fileReader)
		}
		return true
	}

	// kTLS 已启用：明文写裸 fd（内核加密），body 走 sendfile 零拷贝。
	// 裸 fd 为非阻塞，必须经 SyscallConn().Write 回调配合运行时 poller。
	syscallConn, scErr := tlsConn.NetConn().(syscall.Conn).SyscallConn()
	if scErr != nil {
		return true // 已接管且已启用 kTLS，无法回退，只能结束
	}

	var sent int64
	if err = rawWriteAll(syscallConn, head); err != nil {
		return true
	}
	sent += int64(len(head))

	n, sfErr := rawSendfile(syscallConn, int(fileReader.Fd()), fileSize)
	sent += n
	_ = sfErr // 发送错误（如客户端断开）无需特殊处理，连接随后关闭

	if clientConn != nil {
		clientConn.AddSentBytes(sent)
	}
	return true
}

// buildKTLSResponseHead 依据已就绪的响应头构造 HTTP/1.1 响应头部（状态行 + 头 + 空行）
func (this *HTTPRequest) buildKTLSResponseHead(fileSize int64) []byte {
	var header = this.writer.Header()
	if header.Get("Content-Length") == "" {
		header.Set("Content-Length", strconv.FormatInt(fileSize, 10))
	}
	if header.Get("Date") == "" {
		header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}
	// kTLS 路径单请求单连接
	header.Set("Connection", "close")

	var builder strings.Builder
	builder.WriteString("HTTP/1.1 200 OK\r\n")
	_ = header.Write(&builder)
	builder.WriteString("\r\n")
	return []byte(builder.String())
}

// copyFileUserspace 用户态回退拷贝
func (this *HTTPRequest) copyFileUserspace(dst *tls.Conn, src *os.File) (int64, error) {
	var pool = this.bytePool(0)
	var buf = pool.Get()
	defer pool.Put(buf)

	var total int64
	for {
		n, rErr := src.Read(buf.Bytes)
		if n > 0 {
			w, wErr := dst.Write(buf.Bytes[:n])
			total += int64(w)
			if wErr != nil {
				return total, wErr
			}
		}
		if rErr != nil {
			return total, nil
		}
	}
}

// clientConnOfTLS 取 tls.Conn 之下的 *ClientConn（用于流量计费回填）
func clientConnOfTLS(tlsConn *tls.Conn) *ClientConn {
	netConn := tlsConn.NetConn()
	if netConn == nil {
		return nil
	}
	clientConn, _ := netConn.(*ClientConn)
	return clientConn
}

// rawWriteAll 在非阻塞 fd 上完整写入 data，经 poller 等待可写
func rawWriteAll(sc syscall.RawConn, data []byte) error {
	var off int
	var writeErr error
	ctlErr := sc.Write(func(fd uintptr) bool {
		for off < len(data) {
			n, e := unix.Write(int(fd), data[off:])
			if n > 0 {
				off += n
			}
			if e == unix.EAGAIN {
				return false // 等待可写后重试
			}
			if e != nil {
				writeErr = e
				return true
			}
			if n == 0 {
				return true
			}
		}
		return true
	})
	if ctlErr != nil {
		return ctlErr
	}
	return writeErr
}

// rawSendfile 在非阻塞 fd 上用 sendfile 发送 srcFd 的前 size 字节，经 poller 等待可写
func rawSendfile(sc syscall.RawConn, srcFd int, size int64) (int64, error) {
	var offset int64
	var sent int64
	var sfErr error
	ctlErr := sc.Write(func(fd uintptr) bool {
		for sent < size {
			var chunk = size - sent
			if chunk > 1<<30 {
				chunk = 1 << 30
			}
			n, e := unix.Sendfile(int(fd), srcFd, &offset, int(chunk))
			if n > 0 {
				sent += int64(n)
			}
			if e == unix.EAGAIN {
				return false // 等待可写后重试
			}
			if e != nil {
				sfErr = e
				return true
			}
			if n == 0 {
				return true
			}
		}
		return true
	})
	if ctlErr != nil {
		return sent, ctlErr
	}
	return sent, sfErr
}
