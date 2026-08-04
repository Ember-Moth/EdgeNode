// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !linux

package nodes

import "os"

func (this *HTTPRequest) canUseKTLSSendFile(fileSize int64, hasRanges bool) bool {
	return false
}

func (this *HTTPRequest) canUseKTLSCacheHit(bodySize int64) bool {
	return false
}

func (this *HTTPRequest) sendFileKTLS(fp *os.File, offset int64, size int64, status int) (handled bool) {
	return false
}
