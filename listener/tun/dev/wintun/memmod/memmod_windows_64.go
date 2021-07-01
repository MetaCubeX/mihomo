// +build windows,amd64 windows,arm64

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package memmod

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func (opthdr *IMAGE_OPTIONAL_HEADER) imageOffset() uintptr {
	return uintptr(opthdr.ImageBase & 0xffffffff00000000)
}

func (module *Module) check4GBBoundaries(alignedImageSize uintptr) (err error) {
	for (module.codeBase >> 32) < ((module.codeBase + alignedImageSize) >> 32) {
		node := &addressList{
			next:    module.blockedMemory,
			address: module.codeBase,
		}
		module.blockedMemory = node
		module.codeBase, err = windows.VirtualAlloc(0,
			alignedImageSize,
			windows.MEM_RESERVE|windows.MEM_COMMIT,
			windows.PAGE_READWRITE)
		if err != nil {
			return fmt.Errorf("Error allocating memory block: %w", err)
		}
	}
	return
}
