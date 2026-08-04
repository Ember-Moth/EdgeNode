// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !linux

package nodes

import "os"

func (this *HTTPRequest) canUseKTLSSendFile(fileSize int64, hasRanges bool) bool {
	return false
}

func (this *HTTPRequest) sendFileKTLS(fileReader *os.File, fileSize int64) (handled bool) {
	return false
}
