// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphole

import (
	"errors"
	"os"
	"path/filepath"
)

func ResolveOutputPath(outputPath, suggested string) (string, error) {
	name := filepath.Base(suggested)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "", errors.New("missing suggested filename")
	}
	if outputPath == "" {
		return name, nil
	}

	info, err := os.Stat(outputPath)
	if err == nil && info.IsDir() {
		return filepath.Join(outputPath, name), nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return outputPath, nil
}

func ResolveDirectoryOutput(outputPath, suggested string) (string, string, error) {
	name := filepath.Base(suggested)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "", "", errors.New("missing suggested directory name")
	}
	if outputPath == "" {
		return ".", name, nil
	}

	info, err := os.Stat(outputPath)
	if err == nil {
		if !info.IsDir() {
			return "", "", errors.New("directory output path points to an existing file")
		}
		return outputPath, name, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}

	return filepath.Dir(outputPath), filepath.Base(outputPath), nil
}
