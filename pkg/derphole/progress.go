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
	out           io.Writer
	total         int64
	start         time.Time
	lastRender    time.Time
	lastRateTime  time.Time
	lastRateBytes int64
	rateBytes     progressEMA
	rateSeconds   progressEMA
	wroteLine     bool
	mu            sync.Mutex
	current       int64
}

func NewProgressReporter(out io.Writer, total int64) *ProgressReporter {
	if out == nil || total < 0 {
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

	p.mu.Lock()
	defer p.mu.Unlock()

	p.current += int64(n)
	if p.current >= p.total {
		return
	}
	now := progressNow()
	if now.Sub(p.lastRender) < 100*time.Millisecond && p.current < p.total {
		return
	}
	p.lastRender = now
	p.renderLocked(false, now)
}

func (p *ProgressReporter) Finish() {
	if p == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.current < p.total {
		p.current = p.total
	}
	p.renderLocked(true, progressNow())
}

func (p *ProgressReporter) renderLocked(final bool, now time.Time) {
	elapsed := now.Sub(p.start)
	if elapsed <= 0 {
		elapsed = time.Millisecond
	}

	rate := p.rateLocked(final, now, elapsed)
	eta := "--:--"
	if p.total > 0 && p.current > 0 && p.current < p.total {
		remaining := float64(p.total-p.current) / rate
		eta = formatProgressDuration(time.Duration(remaining * float64(time.Second)))
	} else if p.total > 0 && p.current >= p.total {
		eta = "00:00"
	}

	percent := 1.0
	if p.total > 0 {
		percent = float64(p.current) / float64(p.total)
		if percent < 0 {
			percent = 0
		}
		if percent > 1 {
			percent = 1
		}
	}

	filled := int(percent * progressBarWidth)
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	bar := strings.Repeat("#", filled) + strings.Repeat(".", progressBarWidth-filled)
	line := fmt.Sprintf(
		"\r%3.0f%%|%s| %s/%s [%s<%s, %s/s]",
		percent*100,
		bar,
		formatProgressBytes(p.current),
		formatProgressBytes(p.total),
		formatProgressDuration(elapsed),
		eta,
		formatProgressBytes(int64(rate)),
	)
	fmt.Fprint(p.out, line)
	p.wroteLine = true
	if final {
		fmt.Fprintln(p.out)
	}
}

func (p *ProgressReporter) rateLocked(final bool, now time.Time, elapsed time.Duration) float64 {
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
