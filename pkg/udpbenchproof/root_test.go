// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvidenceRootRejectsSymlinkEscapesAtEveryArtifactLayer(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	manifest.EvidenceRoot = ""
	decision := Decision{SchemaVersion: decisionSchemaVersion, ManifestSHA256: canonicalManifestDigest(t, manifest), Stage: StageScreening}
	sample := Sample{SchemaVersion: sampleSchemaVersion}
	sweep := ceilingSweepPointRecord{SchemaVersion: 1, Kind: "ceiling-sweep", Point: CeilingSweepPoint{}}
	profile := ceilingProfileRecord{SchemaVersion: 1, Kind: "ceiling-profile"}

	for _, test := range []struct {
		name  string
		role  string
		value any
		open  func(string, ArtifactRef) error
	}{
		{"manifest", "manifest", manifest, func(root string, ref ArtifactRef) error {
			var opened Manifest
			return verifyDecodeEvidence(root, ref, "manifest", &opened)
		}},
		{"decision", "screening", decision, func(root string, ref ArtifactRef) error {
			var opened Decision
			return verifyDecodeEvidence(root, ref, "screening", &opened)
		}},
		{"sample", "sample", sample, func(root string, ref ArtifactRef) error {
			_, err := LoadSampleArtifact(root, ref)
			return err
		}},
		{"sweep", "ceiling-sweep", sweep, func(root string, ref ArtifactRef) error {
			_, err := LoadCeilingSweepArtifact(root, ref)
			return err
		}},
		{"profile", "ceiling-profile", profile, func(root string, ref ArtifactRef) error {
			_, err := LoadCeilingProfileArtifact(root, ref)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			ref := escapedArtifactRef(t, root, test.role, filepath.ToSlash(filepath.Join("evidence", test.name+".json")), test.value)
			if err := test.open(root, ref); err == nil {
				t.Fatalf("%s evidence opened through root-escaping symlink", test.name)
			}
		})
	}
}

func TestValidateSampleRejectsNestedRawEvidenceSymlinkEscape(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	sample := validEvidenceSample(t, manifest, 0, 2100)
	path := filepath.Join(sample.EvidenceRoot, filepath.FromSlash(sample.Capacity.Artifact.Path))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "capacity.json")
	if err := os.WriteFile(outside, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if verdict := ValidateSample(manifest, sample); verdict.Status == "valid" {
		t.Fatal("sample accepted nested raw evidence through root-escaping symlink")
	}
}

func escapedArtifactRef(t *testing.T, root, role, path string, value any) ArtifactRef {
	t.Helper()
	data, err := canonicalJSONBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.WriteFile(outside, data, 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(inside), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, inside); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	return ArtifactRef{Role: role, Path: path, SHA256: DigestBytes(data)}
}
