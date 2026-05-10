// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

import (
	"bufio"
	"bytes"
	"reflect"
	"testing"
)

func TestWriteReadHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := Header{
		Version:  1,
		Kind:     KindFile,
		Name:     "README.md",
		Size:     123,
		Verify:   "7-purple-sausages",
		Metadata: []byte(`{"mode":"0644"}`),
	}

	if err := WriteHeader(&buf, want); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}

	got, err := ReadHeader(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadHeader() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadHeader() = %#v, want %#v", got, want)
	}
}

func TestReadHeaderRejectsBadMagic(t *testing.T) {
	r := bufio.NewReader(bytes.NewBufferString("not-derphole"))
	if _, err := ReadHeader(r); err == nil {
		t.Fatal("ReadHeader() error = nil, want failure")
	}
}
