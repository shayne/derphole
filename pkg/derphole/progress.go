// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphole

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	progressBarWidth      = 20
	progressRateSmoothing = 0.3
)

var progressNow = time.Now

type ProgressReporter struct {
	out             io.Writer
	total           int64
	start           time.Time
	lastRender      time.Time
	lastRateTime    time.Time
	lastRateBytes   int64
	rateBytes       progressEMA
	rateSeconds     progressEMA
	wroteLine       bool
	lastLineLen     int
	onProgress      func(current, total int64)
	lastCallback    time.Time
	mu              sync.Mutex
	current         int64
	externalElapsed time.Duration
	externalRate    bool
}

type progressCallback struct {
	fn             func(current, total int64)
	current, total int64
}

func (cb progressCallback) emit() {
	if cb.fn != nil {
		cb.fn(cb.current, cb.total)
	}
}

func NewProgressReporter(out io.Writer, total int64) *ProgressReporter {
	return NewProgressReporterWithCallback(out, total, nil)
}

func NewProgressReporterWithCallback(out io.Writer, total int64, onProgress func(current, total int64)) *ProgressReporter {
	if (out == nil && onProgress == nil) || total < 0 {
		return nil
	}
	now := progressNow()
	return &ProgressReporter{
		out:          out,
		total:        total,
		start:        now,
		lastRender:   now,
		lastRateTime: now,
		rateBytes:    newProgressEMA(progressRateSmoothing),
		rateSeconds:  newProgressEMA(progressRateSmoothing),
		onProgress:   onProgress,
	}
}

func (p *ProgressReporter) Wrap(r io.Reader) io.Reader {
	if p == nil {
		return r
	}
	return &progressReader{reader: r, progress: p}
}

func (p *ProgressReporter) Add(n int) {
	if p == nil || n <= 0 {
		return
	}
	p.addLocked(n).emit()
}

func (p *ProgressReporter) addLocked(n int) progressCallback {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.current += int64(n)
	p.externalElapsed = 0
	p.externalRate = false
	if p.current >= p.total {
		return p.callbackLocked(time.Time{})
	}

	now := progressNow()
	callback := p.callbackLocked(now)
	if p.shouldRenderLocked(now) {
		p.lastRender = now
		p.renderLocked(false, now)
	}
	return callback
}

func (p *ProgressReporter) SetWithElapsed(current int64, elapsed time.Duration) {
	if p == nil {
		return
	}

	p.mu.Lock()

	if current < 0 {
		current = 0
	}
	if current > p.total {
		current = p.total
	}
	p.current = current
	p.externalElapsed = elapsed
	p.externalRate = elapsed > 0
	p.lastRateBytes = current
	now := progressNow()
	p.lastRateTime = now
	callback := p.callbackLocked(now)
	if !p.wroteLine || p.shouldRenderLocked(now) {
		p.lastRender = now
		p.renderLocked(false, now)
	}
	p.mu.Unlock()
	callback.emit()
}

func (p *ProgressReporter) Finish() {
	if p == nil {
		return
	}

	var onProgress func(current, total int64)
	var callbackCurrent, callbackTotal int64

	p.mu.Lock()

	if p.current < p.total {
		p.current = p.total
		p.externalElapsed = 0
		p.externalRate = false
	}
	onProgress = p.onProgress
	callbackCurrent = p.current
	callbackTotal = p.total
	p.renderLocked(true, progressNow())
	p.mu.Unlock()

	if onProgress != nil {
		onProgress(callbackCurrent, callbackTotal)
	}
}

func (p *ProgressReporter) Abort() {
	if p == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.wroteLine {
		if p.out == nil {
			return
		}
		_, _ = fmt.Fprintln(p.out)
	}
}

func (p *ProgressReporter) renderLocked(final bool, now time.Time) {
	if p.out == nil {
		return
	}

	elapsed := progressElapsed(p.start, now)
	rate := p.rateLocked(final, now, elapsed)
	line := formatProgressLine(
		progressPercent(p.current, p.total),
		p.current,
		p.total,
		elapsed,
		progressETA(p.current, p.total, rate),
		rate,
	)
	p.writeProgressLineLocked(line, final)
}

func progressElapsed(start, now time.Time) time.Duration {
	elapsed := now.Sub(start)
	if elapsed <= 0 {
		return time.Millisecond
	}
	return elapsed
}

func progressETA(current, total int64, rate float64) string {
	if total <= 0 {
		return "--:--"
	}
	if current >= total {
		return "00:00"
	}
	if current <= 0 || rate <= 0 {
		return "--:--"
	}
	remaining := float64(total-current) / rate
	return formatProgressDuration(time.Duration(remaining * float64(time.Second)))
}

func progressPercent(current, total int64) float64 {
	if total <= 0 {
		return 1
	}
	percent := float64(current) / float64(total)
	if percent < 0 {
		return 0
	}
	if percent > 1 {
		return 1
	}
	return percent
}

func progressBar(percent float64) string {
	filled := int(percent * progressBarWidth)
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	return strings.Repeat("#", filled) + strings.Repeat(".", progressBarWidth-filled)
}

func formatProgressLine(percent float64, current, total int64, elapsed time.Duration, eta string, rate float64) string {
	return fmt.Sprintf(
		"%3.0f%%|%s| %s/%s [%s<%s, %s/s]",
		percent*100,
		progressBar(percent),
		formatProgressBytes(current),
		formatProgressBytes(total),
		formatProgressDuration(elapsed),
		eta,
		formatProgressBytes(int64(rate)),
	)
}

func (p *ProgressReporter) writeProgressLineLocked(line string, final bool) {
	// Match tqdm's status_printer: shorter redraws must erase stale tail chars.
	padding := ""
	if p.lastLineLen > len(line) {
		padding = strings.Repeat(" ", p.lastLineLen-len(line))
	}
	_, _ = fmt.Fprintf(p.out, "\r%s%s", line, padding)
	p.lastLineLen = len(line)
	p.wroteLine = true
	if final {
		_, _ = fmt.Fprintln(p.out)
		p.lastLineLen = 0
	}
}

func (p *ProgressReporter) callbackLocked(now time.Time) progressCallback {
	callback := progressCallback{current: p.current, total: p.total}
	if p.shouldCallbackLocked(now) {
		callback.fn = p.onProgress
	}
	return callback
}

func (p *ProgressReporter) shouldRenderLocked(now time.Time) bool {
	return now.Sub(p.lastRender) >= 100*time.Millisecond || p.current >= p.total
}

func (p *ProgressReporter) shouldCallbackLocked(now time.Time) bool {
	if p.onProgress == nil {
		return false
	}
	if p.lastCallback.IsZero() {
		if now.IsZero() {
			now = progressNow()
		}
		p.lastCallback = now
		return true
	}
	if now.IsZero() {
		now = progressNow()
	}
	if now.Sub(p.lastCallback) < 100*time.Millisecond {
		return false
	}
	p.lastCallback = now
	return true
}

func (p *ProgressReporter) rateLocked(final bool, now time.Time, elapsed time.Duration) float64 {
	if p.externalRate && p.externalElapsed > 0 {
		return float64(p.current) / p.externalElapsed.Seconds()
	}
	if final {
		return float64(p.current) / elapsed.Seconds()
	}

	deltaBytes := p.current - p.lastRateBytes
	deltaTime := now.Sub(p.lastRateTime)
	if deltaBytes > 0 && deltaTime > 0 {
		p.rateBytes.Add(float64(deltaBytes))
		p.rateSeconds.Add(deltaTime.Seconds())
		p.lastRateBytes = p.current
		p.lastRateTime = now
	}

	seconds := p.rateSeconds.Value()
	if seconds > 0 {
		return p.rateBytes.Value() / seconds
	}
	return float64(p.current) / elapsed.Seconds()
}

type progressEMA struct {
	alpha float64
	last  float64
	calls int
}

func newProgressEMA(alpha float64) progressEMA {
	return progressEMA{alpha: alpha}
}

func (e *progressEMA) Add(value float64) {
	beta := 1 - e.alpha
	e.last = e.alpha*value + beta*e.last
	e.calls++
}

func (e progressEMA) Value() float64 {
	if e.calls == 0 {
		return e.last
	}
	beta := 1 - e.alpha
	return e.last / (1 - math.Pow(beta, float64(e.calls)))
}

type progressReader struct {
	reader   io.Reader
	progress *ProgressReporter
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.progress.Add(n)
	}
	return n, err
}

func formatProgressBytes(n int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(n)
	unit := units[0]
	for i := 1; i < len(units) && value >= 1024; i++ {
		value /= 1024
		unit = units[i]
	}
	if unit == "B" {
		return fmt.Sprintf("%d%s", n, unit)
	}
	return fmt.Sprintf("%.1f%s", value, unit)
}

func formatProgressDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalSeconds := int(d.Round(time.Second).Seconds())
	if totalSeconds < 0 {
		totalSeconds = 0
	}
	minutes := totalSeconds / 60
	seconds := totalSeconds % 60
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}
