package probe

import (
	"context"
	"time"
)

const (
	blastRateFeedbackInterval   = 100 * time.Millisecond
	blastRateHoldAfterDecrease  = 600 * time.Millisecond
	blastPacerMaxScheduleDebt   = 250 * time.Millisecond
	blastRateIncreaseMultiplier = 1.08
	blastRateDecreaseMultiplier = 0.75
	blastRateMinMbps            = 64
)

type blastRateFeedback struct {
	SentPayloadBytes     uint64
	ReceivedPayloadBytes uint64
	ReceivedPackets      uint64
	MaxSeqPlusOne        uint64
}

type blastRateController struct {
	rateMbps       int
	ceilingMbps    int
	last           blastRateFeedback
	lastFeedbackAt time.Time
	holdIncrease   time.Time
}

type blastSendControl struct {
	adaptive         bool
	controller       *blastRateController
	sentPayloadBytes uint64
}

type blastPacer struct {
	next time.Time
}

func newBlastRateController(rateMbps int, ceilingMbps int, now time.Time) *blastRateController {
	if rateMbps < 0 {
		rateMbps = 0
	}
	if ceilingMbps < rateMbps {
		ceilingMbps = rateMbps
	}
	return &blastRateController{
		rateMbps:       rateMbps,
		ceilingMbps:    ceilingMbps,
		lastFeedbackAt: now,
	}
}

func newBlastSendControl(rateMbps int, ceilingMbps int, now time.Time) *blastSendControl {
	adaptive := ceilingMbps > 0
	return &blastSendControl{
		adaptive:   adaptive,
		controller: newBlastRateController(rateMbps, ceilingMbps, now),
	}
}

func (c *blastSendControl) Adaptive() bool {
	return c != nil && c.adaptive
}

func (c *blastSendControl) RateMbps() int {
	if c == nil || c.controller == nil {
		return 0
	}
	return c.controller.RateMbps()
}

func (c *blastSendControl) SetSentPayloadBytes(bytes uint64) {
	if c == nil {
		return
	}
	c.sentPayloadBytes = bytes
}

func (c *blastSendControl) ObserveReceiverStats(payload []byte, now time.Time) {
	if c == nil || c.controller == nil {
		return
	}
	stats, ok := unmarshalBlastStatsPayload(payload)
	if !ok {
		return
	}
	before := c.controller.RateMbps()
	c.controller.Observe(now, blastRateFeedback{
		SentPayloadBytes:     c.sentPayloadBytes,
		ReceivedPayloadBytes: stats.ReceivedPayloadBytes,
		ReceivedPackets:      stats.ReceivedPackets,
		MaxSeqPlusOne:        stats.MaxSeqPlusOne,
	})
	after := c.controller.RateMbps()
	if after != before {
		sessionTracef("blast rate update rate_mbps=%d previous_mbps=%d rx_bytes=%d rx_packets=%d rx_max_seq=%d sent_bytes=%d",
			after, before, stats.ReceivedPayloadBytes, stats.ReceivedPackets, stats.MaxSeqPlusOne, c.sentPayloadBytes)
	}
}

func newBlastPacer(now time.Time) *blastPacer {
	return &blastPacer{next: now}
}

func (p *blastPacer) Pace(ctx context.Context, payloadBytes uint64, rateMbps int) error {
	if rateMbps <= 0 || payloadBytes == 0 {
		return nil
	}
	if p == nil {
		return sleepWithContext(ctx, blastPaceDuration(payloadBytes, rateMbps))
	}
	sleepFor := p.schedule(time.Now(), payloadBytes, rateMbps)
	if sleepFor <= 0 {
		return nil
	}
	return sleepWithContext(ctx, sleepFor)
}

func (p *blastPacer) schedule(now time.Time, payloadBytes uint64, rateMbps int) time.Duration {
	if p == nil || rateMbps <= 0 || payloadBytes == 0 {
		return 0
	}
	if now.IsZero() {
		now = time.Now()
	}
	if p.next.IsZero() || now.Sub(p.next) > blastPacerMaxScheduleDebt {
		p.next = now
	}
	p.next = p.next.Add(blastPaceDuration(payloadBytes, rateMbps))
	return p.next.Sub(now)
}

func blastPaceDuration(payloadBytes uint64, rateMbps int) time.Duration {
	if rateMbps <= 0 || payloadBytes == 0 {
		return 0
	}
	return time.Duration((float64(payloadBytes*8) / float64(rateMbps*1000*1000)) * float64(time.Second))
}

func (c *blastRateController) RateMbps() int {
	if c == nil {
		return 0
	}
	return c.rateMbps
}

func (c *blastRateController) Observe(now time.Time, feedback blastRateFeedback) {
	if c == nil || c.rateMbps <= 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if !c.lastFeedbackAt.IsZero() && now.Sub(c.lastFeedbackAt) < blastRateFeedbackInterval {
		return
	}
	sentDelta := deltaUint64(feedback.SentPayloadBytes, c.last.SentPayloadBytes)
	receivedDelta := deltaUint64(feedback.ReceivedPayloadBytes, c.last.ReceivedPayloadBytes)
	receivedPacketDelta := deltaUint64(feedback.ReceivedPackets, c.last.ReceivedPackets)
	missing := feedback.MissingPackets()
	lastMissing := c.last.MissingPackets()
	missingDelta := deltaUint64(missing, lastMissing)

	c.last = feedback
	c.lastFeedbackAt = now

	if sentDelta == 0 {
		return
	}
	loss := missingDelta > blastRateLossBudgetPackets(receivedPacketDelta)
	if loss {
		c.decrease(now)
		return
	}
	clean := receivedDelta > 0 && missing == 0
	if !clean || now.Before(c.holdIncrease) {
		return
	}
	c.increase()
}

func blastRateLossBudgetPackets(receivedDelta uint64) uint64 {
	budget := receivedDelta / 100
	if budget < 8 {
		return 8
	}
	return budget
}

func (f blastRateFeedback) MissingPackets() uint64 {
	return deltaUint64(f.MaxSeqPlusOne, f.ReceivedPackets)
}

func (c *blastRateController) decrease(now time.Time) {
	next := int(float64(c.rateMbps)*blastRateDecreaseMultiplier + 0.5)
	if next < blastRateMinMbps {
		next = blastRateMinMbps
	}
	if next >= c.rateMbps {
		next = c.rateMbps - 1
	}
	if next < blastRateMinMbps {
		next = blastRateMinMbps
	}
	c.rateMbps = next
	c.holdIncrease = now.Add(blastRateHoldAfterDecrease)
}

func (c *blastRateController) increase() {
	if c.ceilingMbps <= 0 || c.rateMbps >= c.ceilingMbps {
		return
	}
	next := int(float64(c.rateMbps)*blastRateIncreaseMultiplier + 0.5)
	if next <= c.rateMbps {
		next = c.rateMbps + 1
	}
	if next > c.ceilingMbps {
		next = c.ceilingMbps
	}
	c.rateMbps = next
}

func deltaUint64(current uint64, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}
