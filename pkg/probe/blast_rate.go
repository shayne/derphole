package probe

import (
	"context"
	"time"
)

const (
	blastRateFeedbackInterval               = 100 * time.Millisecond
	blastRateHoldAfterDecrease              = 1500 * time.Millisecond
	blastRateHoldAfterPressureDecrease      = 5 * time.Second
	blastRateHighCeilingInitialHold         = 500 * time.Millisecond
	blastRateHighCeilingPressureHold        = 1 * time.Second
	blastRateLossConfirmDelay               = 2 * blastRateFeedbackInterval
	blastRateCommitStallWindow              = 500 * time.Millisecond
	blastRateRepairPressureEvery            = blastRateHoldAfterDecrease
	blastPacerMaxScheduleDebt               = 250 * time.Millisecond
	blastRateIncreaseMultiplier             = 1.08
	blastRateHighIncreaseMultiplier         = 1.11
	blastRateLowStartHighIncreaseMultiplier = 1.18
	blastRateMediumIncreaseMultiplier       = 1.02
	blastRateDecreaseMultiplier             = 0.67
	blastRatePressureDecreaseMultiplier     = 0.80
	blastRateLossCeilingMultiplier          = 0.90
	blastRatePressureCeilingMultiplier      = 0.80
	blastRateRepairPressureFloor            = maxRepairRequestSeqs / 2
	blastRateRepairPressureRatio            = 0.001
	blastRateHighRepairPressureRatio        = 0.005
	blastRateConservativeFloorMinMbps       = 300
	blastRateConservativeFloorMaxMbps       = 400
	blastRateConservativeFloorRepairPkts    = maxRepairRequestSeqs * 2
	blastRateHighCeilingPressureFloorMbps   = 100
	blastRateLossBudgetMinPackets           = maxRepairRequestSeqs / 2
	blastRateSevereLossRatioPercent         = 5
	blastRateLossCeilingProbeClean          = 30
	blastRateMediumLossCeilingProbeClean    = 5
	blastRateCleanQueueDelayMax             = 200 * time.Millisecond
	blastRateMinMbps                        = 1
	blastReplayPressureThreshold            = 0.75
)

type blastRateFeedback struct {
	SentPayloadBytes     uint64
	ReceivedPayloadBytes uint64
	ReceivedPackets      uint64
	MaxSeqPlusOne        uint64
}

type blastRateController struct {
	rateMbps           int
	ceilingMbps        int
	lossCeilingMbps    int
	initialLossCeiling bool
	cleanAtLossCeiling int
	last               blastRateFeedback
	lastFeedbackAt     time.Time
	lastProgressBytes  uint64
	lastProgressAt     time.Time
	commitStallAt      time.Time
	holdIncrease       time.Time
	startupLossHold    time.Time
	lossCandidateAt    time.Time
	lossCandidatePk    uint64
}

type blastSendControl struct {
	adaptive         bool
	controller       *blastRateController
	sentPayloadBytes uint64
	ackFloor         uint64
	repairPressureAt time.Time
	repairPressurePk int
}

type blastPacer struct {
	next time.Time
}

func newBlastRateController(rateMbps int, ceilingMbps int, now time.Time) *blastRateController {
	return newBlastRateControllerWithInitialLossCeiling(rateMbps, ceilingMbps, 0, now)
}

func newBlastRateControllerWithInitialLossCeiling(rateMbps int, ceilingMbps int, initialLossCeilingMbps int, now time.Time) *blastRateController {
	if rateMbps < 0 {
		rateMbps = 0
	}
	if ceilingMbps < rateMbps {
		ceilingMbps = rateMbps
	}
	lossCeilingMbps := ceilingMbps
	initialLossCeiling := false
	if initialLossCeilingMbps > 0 && initialLossCeilingMbps < ceilingMbps {
		if initialLossCeilingMbps < rateMbps {
			initialLossCeilingMbps = rateMbps
		}
		lossCeilingMbps = initialLossCeilingMbps
		initialLossCeiling = true
	}
	initialHold := blastRateHoldAfterDecrease
	if ceilingMbps > 1500 && rateMbps > 0 {
		initialHold = blastRateHighCeilingInitialHold
	}
	return &blastRateController{
		rateMbps:           rateMbps,
		ceilingMbps:        ceilingMbps,
		lossCeilingMbps:    lossCeilingMbps,
		initialLossCeiling: initialLossCeiling,
		lastFeedbackAt:     now,
		lastProgressAt:     now,
		holdIncrease:       now.Add(initialHold),
		startupLossHold:    now.Add(blastRateHoldAfterDecrease),
	}
}

func newBlastSendControl(rateMbps int, ceilingMbps int, now time.Time) *blastSendControl {
	return newBlastSendControlWithInitialLossCeiling(rateMbps, ceilingMbps, 0, now)
}

func newBlastSendControlWithInitialLossCeiling(rateMbps int, ceilingMbps int, initialLossCeilingMbps int, now time.Time) *blastSendControl {
	adaptive := ceilingMbps > 0
	return &blastSendControl{
		adaptive:   adaptive,
		controller: newBlastRateControllerWithInitialLossCeiling(rateMbps, ceilingMbps, initialLossCeilingMbps, now),
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

func (c *blastSendControl) AckFloor() uint64 {
	if c == nil {
		return 0
	}
	return c.ackFloor
}

func (c *blastSendControl) ObserveReplayPressure(now time.Time, retainedBytes uint64, maxBytes uint64) {
	if c == nil || c.controller == nil || maxBytes == 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if float64(retainedBytes)/float64(maxBytes) < blastReplayPressureThreshold {
		return
	}
	before := c.controller.RateMbps()
	c.controller.decreaseFromReplayPressure(now)
	after := c.controller.RateMbps()
	if after != before {
		sessionTracef("blast rate replay pressure rate_mbps=%d previous_mbps=%d retained_bytes=%d max_bytes=%d",
			after, before, retainedBytes, maxBytes)
	}
}

func (c *blastSendControl) ObserveRepairPressure(now time.Time, retransmits int) {
	if c == nil || c.controller == nil || c.controller.RateMbps() <= blastRateMinMbps {
		return
	}
	if retransmits <= 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if c.repairPressureAt.IsZero() || now.Sub(c.repairPressureAt) >= blastRateRepairPressureEvery {
		c.repairPressureAt = now
		c.repairPressurePk = 0
	}
	c.repairPressurePk += retransmits
	if c.repairPressurePk < c.repairPressurePackets() {
		return
	}
	if now.Before(c.controller.holdIncrease) {
		c.repairPressureAt = now
		c.repairPressurePk = 0
		return
	}
	before := c.controller.RateMbps()
	c.controller.decreaseFromRepairPressure(now)
	after := c.controller.RateMbps()
	if after != before {
		c.repairPressureAt = now
		c.repairPressurePk = 0
		sessionTracef("blast rate repair pressure rate_mbps=%d previous_mbps=%d retransmits=%d", after, before, retransmits)
	}
}

func (c *blastSendControl) repairPressurePackets() int {
	if c == nil || c.controller == nil {
		return blastRateRepairPressurePackets(0)
	}
	return blastRateRepairPressurePacketsFor(c.controller.RateMbps(), c.controller.ceilingMbps)
}

func blastRateRepairPressurePackets(rateMbps int) int {
	return blastRateRepairPressurePacketsFor(rateMbps, 0)
}

func blastRateRepairPressurePacketsFor(rateMbps int, ceilingMbps int) int {
	if rateMbps <= 0 {
		return blastRateRepairPressureFloor
	}
	floor := blastRateRepairPressureFloor
	if rateMbps >= blastRateConservativeFloorMinMbps && rateMbps <= blastRateConservativeFloorMaxMbps {
		floor = blastRateConservativeFloorRepairPkts
	}
	ratio := blastRateRepairPressureRatio
	if ceilingMbps > 1500 {
		ratio = blastRateHighRepairPressureRatio
	}
	payloadBytes := float64(rateMbps) * 1000 * 1000 / 8 * blastRateRepairPressureEvery.Seconds() * ratio
	packets := int(payloadBytes / defaultChunkSize)
	if packets < floor {
		return floor
	}
	return packets
}

func (c *blastSendControl) ObserveReceiverStats(payload []byte, now time.Time) {
	if c == nil || c.controller == nil {
		return
	}
	stats, ok := unmarshalBlastStatsPayload(payload)
	if !ok {
		return
	}
	c.ObserveReceiverStatsPayload(stats, now, true)
}

func (c *blastSendControl) ObserveReceiverStatsPayload(stats blastReceiverStats, now time.Time, updateAckFloor bool) {
	if c == nil || c.controller == nil {
		return
	}
	if updateAckFloor && stats.AckFloor > c.ackFloor {
		c.ackFloor = stats.AckFloor
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

func blastSocketPacingRateMbps(initialRateMbps int, ceilingMbps int) int {
	if ceilingMbps > initialRateMbps {
		return ceilingMbps
	}
	return initialRateMbps
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
	if feedback.ReceivedPayloadBytes > c.lastProgressBytes {
		c.lastProgressBytes = feedback.ReceivedPayloadBytes
		c.lastProgressAt = now
		c.commitStallAt = time.Time{}
	}

	if sentDelta == 0 {
		return
	}
	if c.shouldBackOffForCommitStall(now, feedback, receivedDelta) {
		c.decreaseFromCommitStall(now)
		c.commitStallAt = now
		return
	}
	loss := missing > blastRateLossBudgetPackets(feedback.ReceivedPackets) &&
		missingDelta > blastRateLossBudgetPackets(receivedPacketDelta)
	if loss {
		if c.shouldHoldMediumStartupLoss(now) {
			c.clearLossCandidate()
			return
		}
		if c.deferModerateLoss(now, missing, missingDelta, receivedPacketDelta, feedback.ReceivedPackets) {
			return
		}
		c.clearLossCandidate()
		c.decrease(now)
		return
	}
	c.clearLossCandidate()
	clean := receivedDelta > 0 && missing == 0
	if !clean || now.Before(c.holdIncrease) {
		return
	}
	if blastRateFeedbackQueueDelay(feedback, c.rateMbps) > blastRateCleanQueueDelayMax {
		return
	}
	c.increase()
}

func (c *blastRateController) shouldHoldMediumStartupLoss(now time.Time) bool {
	if c == nil || c.ceilingMbps <= 0 || c.ceilingMbps > 700 {
		return false
	}
	if c.rateMbps >= c.ceilingMbps {
		return false
	}
	if c.rateMbps < blastRateConservativeFloorMinMbps {
		return false
	}
	return !c.startupLossHold.IsZero() && now.Before(c.startupLossHold)
}

func blastRateLossBudgetPackets(receivedDelta uint64) uint64 {
	budget := receivedDelta / 100
	if budget < blastRateLossBudgetMinPackets {
		return blastRateLossBudgetMinPackets
	}
	return budget
}

func (f blastRateFeedback) MissingPackets() uint64 {
	return deltaUint64(f.MaxSeqPlusOne, f.ReceivedPackets)
}

func blastRateFeedbackQueueDelay(feedback blastRateFeedback, rateMbps int) time.Duration {
	if rateMbps <= 0 || feedback.SentPayloadBytes <= feedback.ReceivedPayloadBytes {
		return 0
	}
	inFlightBytes := feedback.SentPayloadBytes - feedback.ReceivedPayloadBytes
	return time.Duration((float64(inFlightBytes*8) / float64(rateMbps*1000*1000)) * float64(time.Second))
}

func (c *blastRateController) deferModerateLoss(now time.Time, missing uint64, missingDelta uint64, receivedPacketDelta uint64, receivedPackets uint64) bool {
	if c == nil || blastRateSevereLoss(missing, missingDelta, receivedPacketDelta, receivedPackets) {
		return false
	}
	if c.lossCeilingMbps > 0 && c.ceilingMbps > 0 && c.lossCeilingMbps < c.ceilingMbps {
		return false
	}
	if c.lossCandidateAt.IsZero() || missing < c.lossCandidatePk {
		c.lossCandidateAt = now
		c.lossCandidatePk = missing
		return true
	}
	if now.Sub(c.lossCandidateAt) < blastRateLossConfirmDelay {
		if missing > c.lossCandidatePk {
			c.lossCandidatePk = missing
		}
		return true
	}
	return false
}

func (c *blastRateController) clearLossCandidate() {
	if c == nil {
		return
	}
	c.lossCandidateAt = time.Time{}
	c.lossCandidatePk = 0
}

func blastRateSevereLoss(missing uint64, missingDelta uint64, receivedPacketDelta uint64, receivedPackets uint64) bool {
	return blastRateRatioAtLeast(missing, receivedPackets, blastRateSevereLossRatioPercent) ||
		blastRateRatioAtLeast(missingDelta, receivedPacketDelta, blastRateSevereLossRatioPercent)
}

func blastRateRatioAtLeast(numerator uint64, denominator uint64, percent uint64) bool {
	if numerator == 0 {
		return false
	}
	if denominator == 0 {
		return true
	}
	return numerator*100 >= denominator*percent
}

func (c *blastRateController) decrease(now time.Time) {
	c.decreaseWithCeiling(now, false, true)
}

func (c *blastRateController) decreaseFromReplayPressure(now time.Time) {
	c.decreaseWithCeiling(now, true, true)
}

func (c *blastRateController) decreaseFromRepairPressure(now time.Time) {
	capLossCeiling := c == nil || c.ceilingMbps <= 1500 || c.initialLossCeiling
	c.decreaseWithCeiling(now, true, capLossCeiling)
}

func (c *blastRateController) decreaseFromCommitStall(now time.Time) {
	c.decreaseWithCeiling(now, true, true)
}

func (c *blastRateController) shouldBackOffForCommitStall(now time.Time, feedback blastRateFeedback, receivedDelta uint64) bool {
	if c == nil || c.rateMbps <= blastRateMinMbps {
		return false
	}
	if receivedDelta > 0 || feedback.SentPayloadBytes <= feedback.ReceivedPayloadBytes {
		return false
	}
	if c.lastProgressAt.IsZero() || now.Sub(c.lastProgressAt) < blastRateCommitStallWindow {
		return false
	}
	if !c.commitStallAt.IsZero() && now.Sub(c.commitStallAt) < c.pressureHoldAfterDecrease() {
		return false
	}
	return true
}

func (c *blastRateController) decreaseWithCeiling(now time.Time, forceLossCeiling bool, capLossCeiling bool) {
	previous := c.rateMbps
	decreaseMultiplier := blastRateDecreaseMultiplier
	if forceLossCeiling {
		decreaseMultiplier = blastRatePressureDecreaseMultiplier
	}
	next := int(float64(c.rateMbps)*decreaseMultiplier + 0.5)
	if next < blastRateMinMbps {
		next = blastRateMinMbps
	}
	if next >= c.rateMbps {
		next = c.rateMbps - 1
	}
	if next < blastRateMinMbps {
		next = blastRateMinMbps
	}
	if floor := c.mediumRateFloorMbps(); floor > 0 && previous >= floor && next < floor {
		next = floor
	}
	if capLossCeiling {
		c.rememberLossCeiling(previous, next, forceLossCeiling)
	}
	c.rateMbps = next
	hold := blastRateHoldAfterDecrease
	if forceLossCeiling {
		hold = c.pressureHoldAfterDecrease()
	}
	c.holdIncrease = now.Add(hold)
}

func (c *blastRateController) mediumRateFloorMbps() int {
	if c == nil || c.ceilingMbps <= 0 {
		return 0
	}
	if c.ceilingMbps > 700 {
		return blastRateHighCeilingPressureFloorMbps
	}
	floor := int(float64(c.ceilingMbps)*0.40 + 0.5)
	if floor < blastRateMinMbps {
		return blastRateMinMbps
	}
	return floor
}

func (c *blastRateController) pressureHoldAfterDecrease() time.Duration {
	if c != nil && c.ceilingMbps > 0 && c.ceilingMbps <= 700 {
		return blastRateHoldAfterDecrease
	}
	if c != nil && c.ceilingMbps > 1500 {
		return blastRateHighCeilingPressureHold
	}
	return blastRateHoldAfterPressureDecrease
}

func (c *blastRateController) increase() {
	ceiling := c.effectiveCeilingMbps()
	if ceiling <= 0 {
		return
	}
	if c.rateMbps >= ceiling {
		reopened, rateSet := c.maybeReopenLossCeiling()
		if !reopened {
			return
		}
		if rateSet {
			return
		}
		ceiling = c.effectiveCeilingMbps()
		if c.rateMbps >= ceiling {
			return
		}
	}
	next := int(float64(c.rateMbps)*c.increaseMultiplier() + 0.5)
	if next <= c.rateMbps {
		next = c.rateMbps + 1
	}
	if next > ceiling {
		next = ceiling
	}
	c.rateMbps = next
}

func (c *blastRateController) increaseMultiplier() float64 {
	if c != nil && c.ceilingMbps > 1500 && c.rateMbps < 700 {
		return blastRateLowStartHighIncreaseMultiplier
	}
	if c != nil && c.ceilingMbps > 1500 {
		return blastRateHighIncreaseMultiplier
	}
	if c != nil && c.ceilingMbps > 0 && c.ceilingMbps <= 700 {
		return blastRateMediumIncreaseMultiplier
	}
	return blastRateIncreaseMultiplier
}

func (c *blastRateController) effectiveCeilingMbps() int {
	if c == nil || c.ceilingMbps <= 0 {
		return 0
	}
	if c.lossCeilingMbps > 0 && c.lossCeilingMbps < c.ceilingMbps {
		return c.lossCeilingMbps
	}
	return c.ceilingMbps
}

func (c *blastRateController) rememberLossCeiling(previous int, next int, force bool) {
	if c == nil || c.ceilingMbps <= 0 || previous <= 0 {
		return
	}
	if !force && c.initialLossCeiling && c.lossCeilingMbps > 0 && previous <= c.lossCeilingMbps {
		c.cleanAtLossCeiling = 0
		return
	}
	c.initialLossCeiling = false
	if c.lossCeilingMbps <= 0 || c.lossCeilingMbps > c.ceilingMbps {
		c.lossCeilingMbps = c.ceilingMbps
	}
	ceilingMultiplier := blastRateLossCeilingMultiplier
	if force {
		ceilingMultiplier = blastRatePressureCeilingMultiplier
	}
	ceiling := int(float64(previous)*ceilingMultiplier + 0.5)
	if ceiling < next {
		ceiling = next
	}
	if ceiling < blastRateMinMbps {
		ceiling = blastRateMinMbps
	}
	if ceiling > c.ceilingMbps {
		ceiling = c.ceilingMbps
	}
	if force || ceiling < c.lossCeilingMbps {
		c.lossCeilingMbps = ceiling
	}
	c.cleanAtLossCeiling = 0
}

func (c *blastRateController) maybeReopenLossCeiling() (bool, bool) {
	if c == nil || c.ceilingMbps <= 0 || c.lossCeilingMbps <= 0 || c.lossCeilingMbps >= c.ceilingMbps {
		return false, false
	}
	c.cleanAtLossCeiling++
	if c.cleanAtLossCeiling < c.lossCeilingProbeCleanSamples() {
		return false, false
	}
	if c.initialLossCeiling && c.ceilingMbps > 1500 {
		nextRate := int(float64(c.lossCeilingMbps)*1.25 + 0.5)
		if nextRate <= c.rateMbps {
			nextRate = c.rateMbps + 1
		}
		if nextRate > c.ceilingMbps {
			nextRate = c.ceilingMbps
		}
		c.lossCeilingMbps = c.ceilingMbps
		c.initialLossCeiling = false
		c.cleanAtLossCeiling = 0
		c.rateMbps = nextRate
		return true, true
	}
	next := int(float64(c.lossCeilingMbps)*blastRateIncreaseMultiplier + 0.5)
	if next <= c.lossCeilingMbps {
		next = c.lossCeilingMbps + 1
	}
	if next > c.ceilingMbps {
		next = c.ceilingMbps
	}
	c.lossCeilingMbps = next
	c.cleanAtLossCeiling = 0
	return true, false
}

func (c *blastRateController) lossCeilingProbeCleanSamples() int {
	if c != nil && c.initialLossCeiling {
		return blastRateMediumLossCeilingProbeClean
	}
	if c != nil && c.ceilingMbps > 0 && c.ceilingMbps <= 700 {
		return blastRateMediumLossCeilingProbeClean
	}
	return blastRateLossCeilingProbeClean
}

func deltaUint64(current uint64, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}
