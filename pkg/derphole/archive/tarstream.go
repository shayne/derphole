// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func StreamTar(w io.Writer, srcRoot string) error {
	info, err := os.Stat(srcRoot)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", srcRoot)
	}

	tw := tar.NewWriter(w)
	defer func() { _ = tw.Close() }()

	return filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == srcRoot {
			return nil
		}
		return streamTarEntry(tw, srcRoot, path, d)
	})
}

func streamTarEntry(tw *tar.Writer, srcRoot string, path string, d fs.DirEntry) error {
	info, err := d.Info()
	if err != nil {
		return err
	}

	rel, err := filepath.Rel(srcRoot, path)
	if err != nil {
		return err
	}
	name := filepath.ToSlash(rel)

	switch {
	case info.IsDir():
		return writeTarDir(tw, info, name)
	case info.Mode().IsRegular():
		return writeTarFile(tw, info, name, path)
	default:
		return fmt.Errorf("unsupported directory entry %q with mode %v", path, info.Mode())
	}
}

func writeTarDir(tw *tar.Writer, info fs.FileInfo, name string) error {
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = name + "/"
	return tw.WriteHeader(hdr)
}

func writeTarFile(tw *tar.Writer, info fs.FileInfo, name string, path string) error {
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(tw, f)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func ExtractTar(r io.Reader, destRoot, topLevel string) error {
	base := filepath.Join(destRoot, topLevel)
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		target, err := safeTarTarget(base, hdr.Name)
		if err != nil {
			return err
		}
		if err := extractTarEntry(tr, hdr, target); err != nil {
			return err
		}
	}
}

func safeTarTarget(base string, name string) (string, error) {
	clean := filepath.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("unsafe tar path %q", name)
	}

	target := filepath.Join(base, clean)
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe tar target %q", name)
	}
	return target, nil
}

func extractTarEntry(tr *tar.Reader, hdr *tar.Header, target string) error {
	switch hdr.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(target, fs.FileMode(hdr.Mode))
	case tar.TypeReg:
		return extractTarFile(tr, hdr, target)
	default:
		return fmt.Errorf("unsupported tar entry type %d for %q", hdr.Typeflag, hdr.Name)
	}
}

func extractTarFile(tr *tar.Reader, hdr *tar.Header, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(hdr.Mode))
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(f, tr, hdr.Size)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
