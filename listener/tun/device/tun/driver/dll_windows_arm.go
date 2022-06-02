/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package driver

import (
	_ "embed"
)

//go:embed arm/wintun.dll
var dllContent []byte
