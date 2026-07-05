// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package endpointlookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type FileRegistry struct {
	Path string
	Now  func() time.Time
}

type fileRegistryData struct {
	Version int               `json:"version"`
	Records map[string]Record `json:"records"`
}

func (r FileRegistry) Resolve(ctx context.Context, name string, kind Kind) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if err := ValidateName(name); err != nil {
		return Record{}, err
	}
	if err := ValidateKind(kind); err != nil {
		return Record{}, err
	}
	data, err := r.read()
	if err != nil {
		return Record{}, err
	}
	record, ok := data.Records[name]
	if !ok || record.Kind != kind {
		return Record{}, ErrNotFound
	}
	if record.Expired(r.now()) {
		return Record{}, ErrExpired
	}
	return record, nil
}

func (r FileRegistry) Publish(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRecord(record); err != nil {
		return err
	}
	if record.Expired(r.now()) {
		return ErrExpired
	}
	data, err := r.read()
	if err != nil {
		return err
	}
	data.Records[record.Name] = record
	return r.write(data)
}

func (r FileRegistry) Remove(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateName(name); err != nil {
		return err
	}
	data, err := r.read()
	if err != nil {
		return err
	}
	if _, ok := data.Records[name]; !ok {
		return ErrNotFound
	}
	delete(data.Records, name)
	return r.write(data)
}

func (r FileRegistry) List(ctx context.Context) ([]RecordSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := r.read()
	if err != nil {
		return nil, err
	}
	now := r.now()
	summaries := make([]RecordSummary, 0, len(data.Records))
	for _, record := range data.Records {
		if record.Expired(now) {
			continue
		}
		summaries = append(summaries, record.RedactedSummary())
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Name < summaries[j].Name
	})
	return summaries, nil
}

func validateRecord(record Record) error {
	if record.Version != recordVersion {
		return fmt.Errorf("invalid endpoint lookup record version")
	}
	if err := ValidateName(record.Name); err != nil {
		return err
	}
	if err := ValidateKind(record.Kind); err != nil {
		return err
	}
	if record.Value == "" {
		return ErrNotFound
	}
	return nil
}

func (r FileRegistry) read() (fileRegistryData, error) {
	if r.Path == "" {
		return fileRegistryData{}, fmt.Errorf("endpoint lookup registry path is required")
	}
	raw, err := os.ReadFile(r.Path)
	if errors.Is(err, os.ErrNotExist) {
		return newFileRegistryData(), nil
	}
	if err != nil {
		return fileRegistryData{}, err
	}
	var data fileRegistryData
	if err := json.Unmarshal(raw, &data); err != nil {
		return fileRegistryData{}, err
	}
	if data.Records == nil {
		data.Records = make(map[string]Record)
	}
	return data, nil
}

func (r FileRegistry) write(data fileRegistryData) error {
	if r.Path == "" {
		return fmt.Errorf("endpoint lookup registry path is required")
	}
	data.Version = recordVersion
	if data.Records == nil {
		data.Records = make(map[string]Record)
	}
	dir := filepath.Dir(r.Path)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".endpointlookup-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := encodePrivateRegistry(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, r.Path); err != nil {
		return err
	}
	return os.Chmod(r.Path, 0o600)
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

func encodePrivateRegistry(file *os.File, data fileRegistryData) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (r FileRegistry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func newFileRegistryData() fileRegistryData {
	return fileRegistryData{
		Version: recordVersion,
		Records: make(map[string]Record),
	}
}
