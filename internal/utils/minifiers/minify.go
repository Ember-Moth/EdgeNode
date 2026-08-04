// Copyright 2024 GoEdge CDN goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package minifiers

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
)

// 单次优化的最大响应体，超过则跳过，避免占用过多内存
const maxMinifyBodySize = 8 << 20 // 8MB

// MinifyResponse minify response body.
// url 参数当前未参与压缩决策，保留以匹配调用点签名，并为将来按URL细分压缩规则预留。
func MinifyResponse(config *serverconfigs.HTTPPageOptimizationConfig, url string, resp *http.Response) error {
	if config == nil || !config.IsOn() || resp == nil || resp.Body == nil {
		return nil
	}

	// 已压缩的内容无法直接处理（回源解压发生在更早阶段，这里仅兜底）
	if len(resp.Header.Get("Content-Encoding")) > 0 {
		return nil
	}

	var mediaType = mediaTypeFromContentType(resp.Header.Get("Content-Type"))
	var minifier = minifierFor(config, mediaType)
	if minifier == nil {
		return nil
	}

	// 已知超过上限：直接透传原始流，不读取、不优化
	if resp.ContentLength > maxMinifyBodySize {
		return nil
	}

	// 读取至多 max+1 字节以判断是否超限；注意不能提前关闭原始流，
	// 否则超限时无法把剩余内容补回，会造成响应截断。
	var origBody = resp.Body
	body, err := io.ReadAll(io.LimitReader(origBody, maxMinifyBodySize+1))
	if err != nil {
		// 读取失败：把已读部分与剩余原始流拼接后交回，由调用方处理错误
		resp.Body = &multiReadCloser{reader: io.MultiReader(bytes.NewReader(body), origBody), closer: origBody}
		return err
	}
	if len(body) > maxMinifyBodySize {
		// 超过上限（含 chunked 长度未知的情况）：透传完整响应，不做优化、不截断。
		// 用 MultiReader 把已读的前缀与尚未读取的剩余流拼回，Close 仍关原始流。
		resp.Body = &multiReadCloser{reader: io.MultiReader(bytes.NewReader(body), origBody), closer: origBody}
		return nil
	}

	// 未超限说明原始流已读尽，可安全关闭
	_ = origBody.Close()

	var buf = &bytes.Buffer{}
	err = minifier.Minify(sharedMinifier, buf, bytes.NewReader(body), nil)
	if err != nil {
		// 优化失败（例如源内容不合法）：原样返回，不影响正常响应
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		return nil
	}

	var newBody = buf.Bytes()
	resp.Body = io.NopCloser(bytes.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	return nil
}

// 根据Content-Type提取媒体类型（去掉charset等参数）
func mediaTypeFromContentType(contentType string) string {
	if len(contentType) == 0 {
		return ""
	}
	var index = strings.Index(contentType, ";")
	if index >= 0 {
		contentType = contentType[:index]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

// 根据媒体类型和配置选择对应的minifier，未启用则返回nil
func minifierFor(config *serverconfigs.HTTPPageOptimizationConfig, mediaType string) minify.Minifier {
	switch mediaType {
	case "text/html":
		if config.HTML != nil && config.HTML.IsOn {
			return newHTMLMinifier(config.HTML)
		}
	case "text/css":
		if config.CSS != nil && config.CSS.IsOn {
			return &css.Minifier{}
		}
	case "application/javascript", "text/javascript", "application/x-javascript":
		if config.Javascript != nil && config.Javascript.IsOn {
			return &js.Minifier{}
		}
	}
	return nil
}

// 依据HTML配置构造minifier
func newHTMLMinifier(htmlConfig *serverconfigs.HTTPHTMLOptimizationConfig) *html.Minifier {
	return &html.Minifier{
		KeepComments:            htmlConfig.KeepComments,
		KeepConditionalComments: htmlConfig.KeepConditionalComments,
		KeepDefaultAttrVals:     htmlConfig.KeepDefaultAttrVals,
		KeepDocumentTags:        htmlConfig.KeepDocumentTags,
		KeepEndTags:             htmlConfig.KeepEndTags,
		KeepQuotes:              htmlConfig.KeepQuotes,
		KeepWhitespace:          htmlConfig.KeepWhitespace,
	}
}

// 共享的minify引擎，minifier通过参数直接传入，无需注册表
var sharedMinifier = minify.New()

// multiReadCloser 把 Reader 与独立的 Closer 组合，用于超限透传时拼接已读前缀与原始流剩余部分
type multiReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (this *multiReadCloser) Read(p []byte) (int, error) { return this.reader.Read(p) }
func (this *multiReadCloser) Close() error               { return this.closer.Close() }
