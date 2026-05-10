// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import "time"

const intervalStatsMinWindow = blastRateFeedbackInterval

type intervalStats struct {
	lastAt    time.Time
	lastBytes int64
	seen      bool
	peakMbps  float64
	minWindow time.Duration
}

func (s *intervalStats) Observe(now time.Time, totalBytes int64) {
	if s == nil || totalBytes < 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if !s.seen {
		s.observeFirst(now, totalBytes)
		return
	}
	if totalBytes <= s.lastBytes {
		return
	}
	elapsed := now.Sub(s.lastAt)
	if elapsed <= 0 || elapsed < s.effectiveMinWindow() {
		return
	}
	s.observeRate(now, totalBytes, elapsed)
}

func (s *intervalStats) ObserveCompletion(now time.Time, totalBytes int64) {
	if s == nil || totalBytes < 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if !s.seen {
		s.observeFirst(now, totalBytes)
		return
	}
	if totalBytes <= s.lastBytes {
		return
	}
	elapsed := now.Sub(s.lastAt)
	if elapsed <= 0 {
		return
	}
	s.observeRate(now, totalBytes, elapsed)
}

func (s *intervalStats) observeFirst(now time.Time, totalBytes int64) {
	s.seen = true
	s.lastAt = now
	s.lastBytes = totalBytes
}

func (s *intervalStats) effectiveMinWindow() time.Duration {
	if s.minWindow > 0 {
		return s.minWindow
	}
	return intervalStatsMinWindow
}

func (s *intervalStats) observeRate(now time.Time, totalBytes int64, elapsed time.Duration) {
	bytesDelta := totalBytes - s.lastBytes
	mbps := float64(bytesDelta*8) / elapsed.Seconds() / 1_000_000
	if mbps > s.peakMbps {
		s.peakMbps = mbps
	}
	s.lastAt = now
	s.lastBytes = totalBytes
}

func (s *intervalStats) PeakMbps() float64 {
	if s == nil {
		return 0
	}
	return s.peakMbps
}
