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

func TestAppleSSHTunnelScriptIsWiredThroughMise(t *testing.T) {
	script := readScriptFile(t, "apple-ssh-tunnel.sh")
	mise := readRepoFile(t, ".mise.toml")

	if !strings.Contains(mise, `[tasks."apple:ssh-tunnel"]`) {
		t.Fatal(".mise.toml missing apple:ssh-tunnel task")
	}
	if !strings.Contains(mise, `bash ./scripts/apple-ssh-tunnel.sh`) {
		t.Fatal("apple:ssh-tunnel task does not call scripts/apple-ssh-tunnel.sh")
	}
	info, err := os.Stat(filepath.Join(".", "apple-ssh-tunnel.sh"))
	if err != nil {
		t.Fatalf("stat apple-ssh-tunnel.sh: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("apple-ssh-tunnel.sh is not executable")
	}

	for _, want := range []string{
		"go run ./tools/ssh-fixture",
		"derptun serve",
		"wait_for_compact_invite",
		"Invite: (DT1[^[:space:]]+)",
		"DERPHOLE_LIVE_SSH_PAYLOAD",
		"DERPHOLE_LIVE_SSH_USERNAME",
		"DERPHOLE_LIVE_SSH_PASSWORD",
		"testLiveSSHTunnelPayloadOpensTerminal",
		"apple/Derphole/Vendor",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("apple-ssh-tunnel.sh missing %q", want)
		}
	}
}

func TestAppleBuildsUseRepoLocalVendor(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"apple/Derphole/Vendor/libghostty/ios/lib/libghostty.a",
		"apple/Derphole/Vendor/libghostty/ios-simulator/lib/libghostty.a",
		"apple/Derphole/Vendor/libssh2/ios/lib/libssh2.a",
		"apple/Derphole/Vendor/libssh2/ios-simulator/lib/libssh2.a",
		"apple/Derphole/Vendor/libssh2/ios/lib/libssl.a",
		"apple/Derphole/Vendor/libssh2/ios-simulator/lib/libssl.a",
		"apple/Derphole/Vendor/libssh2/ios/lib/libcrypto.a",
		"apple/Derphole/Vendor/libssh2/ios-simulator/lib/libcrypto.a",
	} {
		if _, err := os.Stat(filepath.Join("..", filepath.FromSlash(path))); err != nil {
			t.Fatalf("missing repo-local Apple vendor file %s: %v", path, err)
		}
	}

	for name, contents := range map[string]string{
		".mise.toml":                            readRepoFile(t, ".mise.toml"),
		"apple-ssh-tunnel.sh":                   readScriptFile(t, "apple-ssh-tunnel.sh"),
		"apple-web-tunnel.sh":                   readScriptFile(t, "apple-web-tunnel.sh"),
		"Derphole.xcodeproj/project.pbxproj":    readRepoFile(t, "apple/Derphole/Derphole.xcodeproj/project.pbxproj"),
		"DerpholeUITests/DerpholeUITests.swift": readRepoFile(t, "apple/Derphole/DerpholeUITests/DerpholeUITests.swift"),
	} {
		if strings.Contains(contents, "VENDOR_ROOT") {
			t.Fatalf("%s still references an external vendor root variable", name)
		}
		if strings.Contains(contents, filepath.Join("/", "Users")+"/") {
			t.Fatalf("%s contains an absolute user-home path", name)
		}
	}

	xcodeProject := readRepoFile(t, "apple/Derphole/Derphole.xcodeproj/project.pbxproj")
	for _, want := range []string{
		"$(SRCROOT)/Vendor/libghostty/ios/include",
		"$(SRCROOT)/Vendor/libghostty/ios-simulator/include",
		"$(SRCROOT)/Vendor/libssh2/include",
		"$(SRCROOT)/Vendor/libghostty/ios/lib",
		"$(SRCROOT)/Vendor/libghostty/ios-simulator/lib",
		"$(SRCROOT)/Vendor/libssh2/ios/lib",
		"$(SRCROOT)/Vendor/libssh2/ios-simulator/lib",
	} {
		if !strings.Contains(xcodeProject, want) {
			t.Fatalf("Derphole.xcodeproj missing repo-local vendor path %q", want)
		}
	}
}
