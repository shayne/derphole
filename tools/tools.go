// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build tools

// This file keeps Go-based developer tools in go.mod.
package tools

import (
	_ "github.com/google/addlicense"
	_ "github.com/tailscale/depaware"
)
