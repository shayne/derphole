// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package brand

import "strings"

var wordmarkLines = []string{
	"     _                      _",
	"  __| | ___ _ __ _ __  ___| |__",
	" / _` |/ _ \\ '__| '_ \\/ __| '_ \\",
	"| (_| |  __/ |  | |_) \\__ \\ | | |",
	" \\__,_|\\___|_|  | .__/|___/_| |_|",
	"                 |_|",
}

func WordmarkLines() []string {
	return append([]string(nil), wordmarkLines...)
}

func Wordmark() string {
	return strings.Join(wordmarkLines, "\n")
}
