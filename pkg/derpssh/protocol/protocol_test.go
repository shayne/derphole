// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

import "testing"

func TestNormalizeDisplayName(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "trim", in: "  Alex  ", want: "Alex"},
		{name: "control chars", in: "Al\x1b[31mex", want: "Alex"},
		{name: "osc bell", in: "Al\x1b]0;ignored\aex", want: "Alex"},
		{name: "osc st", in: "Al\x1b]0;ignored\x1b\\ex", want: "Alex"},
		{name: "too long", in: "abcdefghijklmnopqrstuvwxyz0123456789", want: "abcdefghijklmnopqrstuvwx"},
		{name: "empty", in: " \x1b ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDisplayName(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("NormalizeDisplayName() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDisplayName() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeDisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRoleCanWrite(t *testing.T) {
	if RoleRead.CanWrite() {
		t.Fatal("RoleRead.CanWrite() = true, want false")
	}
	if !RoleWrite.CanWrite() {
		t.Fatal("RoleWrite.CanWrite() = false, want true")
	}
}
