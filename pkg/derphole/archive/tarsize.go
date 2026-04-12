package archive

import (
	"archive/tar"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type TarStats struct {
	TarBytes          int64
	FileCount         int
	UncompressedBytes int64
}

func TarSize(srcRoot string) (int64, error) {
	stats, err := DescribeTar(srcRoot)
	if err != nil {
		return 0, err
	}
	return stats.TarBytes, nil
}

func DescribeTar(srcRoot string) (TarStats, error) {
	info, err := os.Stat(srcRoot)
	if err != nil {
		return TarStats{}, err
	}
	if !info.IsDir() {
		return TarStats{}, fmt.Errorf("%q is not a directory", srcRoot)
	}

	var stats TarStats
	if err := filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == srcRoot {
			return nil
		}

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
			headerBytes, err := tarHeaderBytes(info, name+"/")
			if err != nil {
				return err
			}
			stats.TarBytes += headerBytes
			return nil
		case info.Mode().IsRegular():
			headerBytes, err := tarHeaderBytes(info, name)
			if err != nil {
				return err
			}
			stats.TarBytes += headerBytes + padded512(info.Size())
			stats.FileCount++
			stats.UncompressedBytes += info.Size()
			return nil
		default:
			return fmt.Errorf("unsupported directory entry %q with mode %v", path, info.Mode())
		}
	}); err != nil {
		return TarStats{}, err
	}

	stats.TarBytes += 1024
	return stats, nil
}

func tarHeaderBytes(info fs.FileInfo, name string) (int64, error) {
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return 0, err
	}
	hdr.Name = name

	var cw countingWriter
	tw := tar.NewWriter(&cw)
	if err := tw.WriteHeader(hdr); err != nil {
		return 0, err
	}
	return cw.n, nil
}

func padded512(n int64) int64 {
	if n <= 0 {
		return 0
	}
	rem := n % 512
	if rem == 0 {
		return n
	}
	return n + (512 - rem)
}

type countingWriter struct {
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}
