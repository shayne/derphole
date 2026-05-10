// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteSmokeScriptsUseRemoteMktemp(t *testing.T) {
	t.Parallel()

	scripts := []string{
		"smoke-remote.sh",
		"smoke-remote-share.sh",
		"smoke-remote-relay.sh",
		"smoke-remote-derptun.sh",
	}
	for _, name := range scripts {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(filepath.Join(".", name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			body := string(data)
			if !strings.Contains(body, "mktemp -d") {
				t.Fatalf("%s does not create a remote temp directory with mktemp -d", name)
			}
			for _, unsafe := range []string{
				"remote_base=\"/tmp/",
				"remote_upload=\"/tmp/",
				"-$$",
				"rm -f '${remote_base}'.*",
			} {
				if strings.Contains(body, unsafe) {
					t.Fatalf("%s still contains predictable remote temp pattern %q", name, unsafe)
				}
			}
		})
	}
}
