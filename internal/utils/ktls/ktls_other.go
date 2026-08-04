// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !linux

package ktls

// EnableULP 非 Linux 平台不支持 kTLS
func EnableULP(fd int) error {
	return ErrUnsupported
}

// Enable 非 Linux 平台不支持 kTLS
func Enable(fd int, dir Direction, km *KeyMaterial) error {
	return ErrUnsupported
}
