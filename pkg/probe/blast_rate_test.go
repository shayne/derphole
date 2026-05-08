package probe

import (
	"testing"
	"time"
)

func TestBlastRateControllerRampsCleanFeedbackTowardCeiling(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(700, 2250, start)

	sentBytes := uint64(0)
	receivedBytes := uint64(0)
	for i := 1; i <= 32; i++ {
		now := start.Add(time.Duration(i) * blastRateFeedbackInterval)
		sentBytes += 10_000_000
		receivedBytes += 10_000_000
		controller.Observe(now, blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      uint64(i) * 100,
			MaxSeqPlusOne:        uint64(i) * 100,
		})
	}

	if got := controller.RateMbps(); got < 1500 {
		t.Fatalf("RateMbps() = %d, want clean feedback to ramp above 1500", got)
	}
	if got := controller.RateMbps(); got > 2250 {
		t.Fatalf("RateMbps() = %d, want capped at ceiling 2250", got)
	}
}

func TestBlastRateControllerHoldsInitialRateBeforeIncreasing(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(350, 1200, start)

	sentBytes := uint64(0)
	receivedBytes := uint64(0)
	for i := 1; i <= 5; i++ {
		now := start.Add(time.Duration(i) * blastRateFeedbackInterval)
		sentBytes += 4_000_000
		receivedBytes += 4_000_000
		controller.Observe(now, blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      uint64(i) * 100,
			MaxSeqPlusOne:        uint64(i) * 100,
		})
	}

	if got := controller.RateMbps(); got != 350 {
		t.Fatalf("RateMbps() during initial hold = %d, want 350", got)
	}
}

func TestBlastRateControllerHoldsCleanIncreaseWhenReceiverBacklogIsHigh(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(350, 700, start)

	controller.Observe(start.Add(blastRateHoldAfterDecrease+blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     66_430_424,
		ReceivedPayloadBytes: 55_077_920,
		ReceivedPackets:      40_340,
		MaxSeqPlusOne:        40_340,
	})

	if got := controller.RateMbps(); got != 350 {
		t.Fatalf("RateMbps() with high receiver backlog = %d, want 350", got)
	}
}

func TestBlastRateControllerHoldsMediumStartupRateOnReceiverLag(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(350, 700, start)

	controller.Observe(start.Add(blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     31_358_976,
		ReceivedPayloadBytes: 19_553_256,
		ReceivedPackets:      16_614,
		MaxSeqPlusOne:        16_990,
	})
	controller.Observe(start.Add(2*blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     37_407_664,
		ReceivedPayloadBytes: 19_823_704,
		ReceivedPackets:      21_708,
		MaxSeqPlusOne:        23_229,
	})

	if got := controller.RateMbps(); got != 350 {
		t.Fatalf("RateMbps() during medium-ceiling startup receiver lag = %d, want 350", got)
	}
}

func TestBlastRateControllerRampsMediumCeilingConservatively(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(350, 700, start)

	controller.Observe(start.Add(blastRateHoldAfterDecrease+blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     60_000_000,
		ReceivedPayloadBytes: 60_000_000,
		ReceivedPackets:      44_000,
		MaxSeqPlusOne:        44_000,
	})

	if got, wantMax := controller.RateMbps(), 360; got > wantMax {
		t.Fatalf("RateMbps() after one medium-ceiling clean sample = %d, want <= %d", got, wantMax)
	}
}

func TestBlastRateControllerBacksOffWhenFeedbackShowsDeliveryLoss(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(2250, 2250, start)

	controller.Observe(start.Add(blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     100_000_000,
		ReceivedPayloadBytes: 75_000_000,
		ReceivedPackets:      750,
		MaxSeqPlusOne:        1000,
	})

	if got := controller.RateMbps(); got >= 2250 {
		t.Fatalf("RateMbps() = %d, want loss feedback to reduce rate", got)
	}
	if got := controller.RateMbps(); got < 700 {
		t.Fatalf("RateMbps() = %d, want one loss event to stay above conservative floor", got)
	}
}

func TestBlastRateControllerBacksOffWhenCommittedProgressStalls(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(700, 2250, start)

	for i := 1; i <= 6; i++ {
		controller.Observe(start.Add(time.Duration(i)*blastRateFeedbackInterval), blastRateFeedback{
			SentPayloadBytes:     uint64(i) * 8_000_000,
			ReceivedPayloadBytes: 0,
			ReceivedPackets:      uint64(i) * 1000,
			MaxSeqPlusOne:        uint64(i) * 1000,
		})
	}

	if got := controller.RateMbps(); got >= 700 {
		t.Fatalf("RateMbps() = %d, want committed-progress stall to reduce rate below 700", got)
	}
	held := controller.RateMbps()
	controller.Observe(start.Add(7*blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     64_000_000,
		ReceivedPayloadBytes: 0,
		ReceivedPackets:      7000,
		MaxSeqPlusOne:        7000,
	})
	if got := controller.RateMbps(); got != held {
		t.Fatalf("RateMbps() = %d, want stall backoff hold at %d", got, held)
	}
}

func TestBlastRateControllerToleratesSmallTransientMissingWindow(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(2250, 2250, start)

	controller.Observe(start.Add(blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     4_210_128,
		ReceivedPayloadBytes: 3_221_952,
		ReceivedPackets:      2328,
		MaxSeqPlusOne:        2347,
	})

	if got := controller.RateMbps(); got != 2250 {
		t.Fatalf("RateMbps() = %d, want tiny in-flight gap to keep rate 2250", got)
	}
}

func TestBlastRateControllerIgnoresSmallOverallReorderGapAtHighThroughput(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(350, 2250, start)

	controller.Observe(start.Add(blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     56_000_000,
		ReceivedPayloadBytes: 56_000_000,
		ReceivedPackets:      41_500,
		MaxSeqPlusOne:        41_500,
	})
	controller.Observe(start.Add(2*blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     58_327_040,
		ReceivedPayloadBytes: 56_612_480,
		ReceivedPackets:      41_546,
		MaxSeqPlusOne:        41_643,
	})

	if got := controller.RateMbps(); got != 350 {
		t.Fatalf("RateMbps() = %d, want transient 97-packet reorder gap to keep rate 350", got)
	}
}

func TestBlastRateControllerIgnoresSmallStartupReorderGap(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(263, 2250, start)

	controller.Observe(start.Add(blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     5_472_256,
		ReceivedPayloadBytes: 4_474_440,
		ReceivedPackets:      3_313,
		MaxSeqPlusOne:        3_348,
	})

	if got := controller.RateMbps(); got != 263 {
		t.Fatalf("RateMbps() = %d, want startup 35-packet reorder gap to keep rate 263", got)
	}
}

func TestBlastRateControllerDefersModerateTransientReorderBeforeBackoff(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(350, 350, start)

	controller.Observe(start.Add(blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     141_052_848,
		ReceivedPayloadBytes: 127_358_592,
		ReceivedPackets:      96_403,
		MaxSeqPlusOne:        97_958,
	})
	if got := controller.RateMbps(); got != 350 {
		t.Fatalf("RateMbps() after transient reorder sample = %d, want 350", got)
	}

	controller.Observe(start.Add(2*blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     178_408_368,
		ReceivedPayloadBytes: 177_841_624,
		ReceivedPackets:      130_255,
		MaxSeqPlusOne:        130_255,
	})
	if got := controller.RateMbps(); got != 350 {
		t.Fatalf("RateMbps() after reorder clears = %d, want 350", got)
	}
}

func TestBlastRateControllerHoldsAfterLossBeforeIncreasing(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(2000, 2250, start)

	lossAt := start.Add(blastRateFeedbackInterval)
	controller.Observe(lossAt, blastRateFeedback{
		SentPayloadBytes:     100_000_000,
		ReceivedPayloadBytes: 80_000_000,
		ReceivedPackets:      800,
		MaxSeqPlusOne:        1000,
	})
	backedOff := controller.RateMbps()

	controller.Observe(lossAt.Add(blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     110_000_000,
		ReceivedPayloadBytes: 90_000_000,
		ReceivedPackets:      900,
		MaxSeqPlusOne:        1000,
	})
	if got := controller.RateMbps(); got != backedOff {
		t.Fatalf("RateMbps() during hold = %d, want %d", got, backedOff)
	}

	controller.Observe(lossAt.Add(blastRateHoldAfterDecrease+blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     120_000_000,
		ReceivedPayloadBytes: 100_000_000,
		ReceivedPackets:      1000,
		MaxSeqPlusOne:        1000,
	})
	if got := controller.RateMbps(); got <= backedOff {
		t.Fatalf("RateMbps() after clean hold = %d, want above backed-off rate %d", got, backedOff)
	}
}

func TestBlastRateControllerCapsRecentLossCeilingBeforeReprobing(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(350, 350, start)

	lossAt := start.Add(blastRateFeedbackInterval)
	controller.Observe(lossAt, blastRateFeedback{
		SentPayloadBytes:     50_000_000,
		ReceivedPayloadBytes: 45_000_000,
		ReceivedPackets:      45_000,
		MaxSeqPlusOne:        50_000,
	})

	sentBytes := uint64(50_000_000)
	receivedBytes := uint64(45_000_000)
	for i := 1; i <= 8; i++ {
		sentBytes += 2_000_000
		receivedBytes += 2_000_000
		controller.Observe(lossAt.Add(blastRateHoldAfterDecrease+time.Duration(i)*blastRateFeedbackInterval), blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      45_000 + uint64(i)*2_000,
			MaxSeqPlusOne:        45_000 + uint64(i)*2_000,
		})
	}

	if got, wantMax := controller.RateMbps(), 315; got > wantMax {
		t.Fatalf("RateMbps() = %d, want recent loss ceiling <= %d before sustained clean re-probe", got, wantMax)
	}
}

func TestBlastRateControllerReopensRecentLossCeilingAfterSustainedCleanFeedback(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(350, 350, start)

	lossAt := start.Add(blastRateFeedbackInterval)
	controller.Observe(lossAt, blastRateFeedback{
		SentPayloadBytes:     50_000_000,
		ReceivedPayloadBytes: 45_000_000,
		ReceivedPackets:      45_000,
		MaxSeqPlusOne:        50_000,
	})

	sentBytes := uint64(50_000_000)
	receivedBytes := uint64(45_000_000)
	for i := 1; i <= 64; i++ {
		sentBytes += 2_000_000
		receivedBytes += 2_000_000
		controller.Observe(lossAt.Add(blastRateHoldAfterDecrease+time.Duration(i)*blastRateFeedbackInterval), blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      45_000 + uint64(i)*2_000,
			MaxSeqPlusOne:        45_000 + uint64(i)*2_000,
		})
	}

	if got, wantAbove := controller.RateMbps(), 315; got <= wantAbove {
		t.Fatalf("RateMbps() = %d, want sustained clean feedback to re-probe above %d", got, wantAbove)
	}
}

func TestBlastRateControllerTightensLossCeilingAfterBackoffStillLoses(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(514, 1200, start)

	pressureAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(pressureAt, blastRateRepairPressurePackets(control.RateMbps()))
	if got := control.RateMbps(); got != 411 {
		t.Fatalf("RateMbps() after repair pressure = %d, want 411", got)
	}

	samples := []struct {
		sentBytes     uint64
		receivedBytes uint64
		receivedPkts  uint64
		maxSeqPlusOne uint64
	}{
		{49_115_528, 36_072_888, 26_419, 28_397},
		{52_035_584, 39_185_808, 28_698, 32_497},
		{55_856_048, 46_523_032, 34_071, 38_492},
	}
	for i, sample := range samples {
		now := pressureAt.Add(blastRateHoldAfterDecrease + time.Duration(i+1)*blastRateFeedbackInterval)
		control.SetSentPayloadBytes(sample.sentBytes)
		control.controller.Observe(now, blastRateFeedback{
			SentPayloadBytes:     sample.sentBytes,
			ReceivedPayloadBytes: sample.receivedBytes,
			ReceivedPackets:      sample.receivedPkts,
			MaxSeqPlusOne:        sample.maxSeqPlusOne,
		})
	}

	if got, wantMax := control.controller.effectiveCeilingMbps(), 166; got > wantMax {
		t.Fatalf("effectiveCeilingMbps() = %d, want repeated loss after backoff to tighten ceiling <= %d", got, wantMax)
	}
}

func TestBlastRateControllerRecoversConservativelyAfterRepeatedBackoffLoss(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(570, 700, start)

	pressureAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(pressureAt, blastRateRepairPressurePackets(control.RateMbps()))
	lossAt := pressureAt.Add(blastRateFeedbackInterval)
	control.controller.Observe(lossAt, blastRateFeedback{
		SentPayloadBytes:     124_578_848,
		ReceivedPayloadBytes: 113_515_272,
		ReceivedPackets:      83_141,
		MaxSeqPlusOne:        84_570,
	})
	lossAt = lossAt.Add(blastRateFeedbackInterval)
	control.controller.Observe(lossAt, blastRateFeedback{
		SentPayloadBytes:     130_987_536,
		ReceivedPayloadBytes: 122_738_792,
		ReceivedPackets:      89_897,
		MaxSeqPlusOne:        92_612,
	})

	sentBytes := uint64(130_987_536)
	receivedBytes := uint64(122_738_792)
	for i := 1; i <= 40; i++ {
		sentBytes += 2_500_000
		receivedBytes += 2_500_000
		packets := 89_897 + uint64(i)*1_800
		control.controller.Observe(lossAt.Add(blastRateHoldAfterDecrease+time.Duration(i)*blastRateFeedbackInterval), blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      packets,
			MaxSeqPlusOne:        packets,
		})
	}

	if got, wantMax := control.RateMbps(), 320; got > wantMax {
		t.Fatalf("RateMbps() after repeated loss and 40 clean samples = %d, want conservative recovery <= %d", got, wantMax)
	}
}

func TestBlastSendControlBacksOffRepeatedRepairPressureAfterHold(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(525, 700, start)

	firstRepair := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(firstRepair, blastRateRepairPressurePackets(control.RateMbps()))
	firstBackoff := control.RateMbps()
	if firstBackoff >= 525 {
		t.Fatalf("RateMbps() after first repair pressure = %d, want below 525", firstBackoff)
	}

	immediateRepair := firstRepair.Add(blastRateFeedbackInterval)
	control.ObserveRepairPressure(immediateRepair, blastRateRepairPressurePackets(control.RateMbps()))
	if got := control.RateMbps(); got != firstBackoff {
		t.Fatalf("RateMbps() for repair pressure inside post-loss hold = %d, want %d", got, firstBackoff)
	}

	secondRepair := firstRepair.Add(blastRateHoldAfterPressureDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(secondRepair, blastRateRepairPressurePackets(control.RateMbps()))
	if got := control.RateMbps(); got >= firstBackoff {
		t.Fatalf("RateMbps() after repeated repair pressure = %d, want below %d", got, firstBackoff)
	}
}

func TestBlastRateControllerResumesMediumProbingSoonAfterRepairPressure(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(609, 700, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(repairAt, maxRepairRequestSeqs)
	backedOff := control.RateMbps()

	for i := 1; i <= 5; i++ {
		cleanAt := repairAt.Add(blastRateHoldAfterDecrease + time.Duration(i)*blastRateFeedbackInterval)
		sent := uint64(360_000_000 + i*2_000_000)
		received := uint64(359_000_000 + i*2_000_000)
		packets := uint64(263_000 + i*1_500)
		control.SetSentPayloadBytes(sent)
		control.controller.Observe(cleanAt, blastRateFeedback{
			SentPayloadBytes:     sent,
			ReceivedPayloadBytes: received,
			ReceivedPackets:      packets,
			MaxSeqPlusOne:        packets,
		})
	}

	if got := control.RateMbps(); got <= backedOff {
		t.Fatalf("RateMbps() after sustained clean feedback 2s after medium repair pressure = %d, want above backed-off rate %d", got, backedOff)
	}
}

func TestBlastSendControlRepeatedRepairPressureDoesNotCollapseRate(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(1200, 1200, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	for i := 0; i < 6; i++ {
		control.ObserveRepairPressure(repairAt, blastRateRepairPressurePackets(control.RateMbps()))
		repairAt = repairAt.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	}

	if got, wantMin := control.RateMbps(), 700; got < wantMin {
		t.Fatalf("RateMbps() after repeated repair pressure = %d, want >= %d", got, wantMin)
	}
}

func TestBlastSendControlMediumRepairPressureDoesNotCollapseBelowUsefulFloor(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(530, 700, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	for i := 0; i < 6; i++ {
		control.ObserveRepairPressure(repairAt, blastRateRepairPressurePackets(control.RateMbps()))
		repairAt = repairAt.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	}

	if got, wantMin := control.RateMbps(), 280; got < wantMin {
		t.Fatalf("RateMbps() after repeated medium repair pressure = %d, want >= %d", got, wantMin)
	}
}

func TestBlastRateControllerMediumLossFeedbackDoesNotCollapseBelowUsefulFloor(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(435, 700, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(repairAt, blastRateRepairPressurePackets(control.RateMbps()))
	backedOff := control.RateMbps()

	control.controller.Observe(repairAt.Add(blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     153_416_072,
		ReceivedPayloadBytes: 130_830_616,
		ReceivedPackets:      105_458,
		MaxSeqPlusOne:        107_030,
	})

	if got, wantMin := control.RateMbps(), 280; got < wantMin || got >= backedOff {
		t.Fatalf("RateMbps() after medium loss feedback = %d, want >= %d and below %d", got, wantMin, backedOff)
	}
}

func TestBlastSendControlIgnoresSmallRepairPressure(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(525, 700, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	budget := blastRateRepairPressurePackets(control.RateMbps())
	control.ObserveRepairPressure(repairAt, budget-1)
	if got := control.RateMbps(); got != 525 {
		t.Fatalf("RateMbps() below repair-pressure packet threshold = %d, want 525", got)
	}

	control.ObserveRepairPressure(repairAt.Add(blastRateFeedbackInterval), 1)
	if got := control.RateMbps(); got >= 525 {
		t.Fatalf("RateMbps() after accumulated repair pressure = %d, want below 525", got)
	}
}

func TestBlastSendControlIgnoresRateScaledRepairPressureBelowBudget(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(2250, 10_000, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(repairAt, maxRepairRequestSeqs)

	if got := control.RateMbps(); got != 2250 {
		t.Fatalf("RateMbps() after low-overhead repair pressure = %d, want 2250", got)
	}
}

func TestBlastSendControlHighCeilingToleratesModerateRepairPressureBurst(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(1293, 2327, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(repairAt, maxRepairRequestSeqs)
	control.ObserveRepairPressure(repairAt.Add(blastRateFeedbackInterval), maxRepairRequestSeqs)

	if got, want := control.RateMbps(), 1293; got != want {
		t.Fatalf("RateMbps() after moderate high-ceiling repair burst = %d, want %d", got, want)
	}
}

func TestBlastRateControllerHighCeilingStartsProbingAfterShortInitialHold(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(700, 10_000, start)

	controller.Observe(start.Add(600*time.Millisecond), blastRateFeedback{
		SentPayloadBytes:     100_000_000,
		ReceivedPayloadBytes: 100_000_000,
		ReceivedPackets:      73_000,
		MaxSeqPlusOne:        73_000,
	})

	if got, wantAbove := controller.RateMbps(), 700; got <= wantAbove {
		t.Fatalf("RateMbps() after high-ceiling clean startup feedback = %d, want above %d", got, wantAbove)
	}
}

func TestBlastRateControllerLowStartHighCeilingStartsProbingAfterShortInitialHold(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(100, 2250, start)

	controller.Observe(start.Add(600*time.Millisecond), blastRateFeedback{
		SentPayloadBytes:     12_000_000,
		ReceivedPayloadBytes: 12_000_000,
		ReceivedPackets:      8_700,
		MaxSeqPlusOne:        8_700,
	})

	if got, wantAbove := controller.RateMbps(), 100; got <= wantAbove {
		t.Fatalf("RateMbps() after low-start high-ceiling clean startup feedback = %d, want above %d", got, wantAbove)
	}
}

func TestBlastRateControllerLowStartHighCeilingReachesTwoLaneBasisWithinTwoSeconds(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(100, 2250, start)

	sentBytes := uint64(0)
	receivedBytes := uint64(0)
	for i := 1; i <= 20; i++ {
		sentBytes += 8_000_000
		receivedBytes += 8_000_000
		packets := uint64(i) * 5_800
		controller.Observe(start.Add(time.Duration(i)*blastRateFeedbackInterval), blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      packets,
			MaxSeqPlusOne:        packets,
		})
	}

	if got, wantMin := controller.RateMbps(), 700; got < wantMin {
		t.Fatalf("RateMbps() after low-start high-ceiling clean ramp = %d, want >= %d", got, wantMin)
	}
	if got, wantMax := controller.RateMbps(), 2250; got > wantMax {
		t.Fatalf("RateMbps() after low-start high-ceiling clean ramp = %d, want <= %d", got, wantMax)
	}
}

func TestBlastRateControllerHighCeilingReplayPressureKeepsUsefulFloor(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(1200, 1800, start)

	for i := 1; i <= 20; i++ {
		controller.decreaseFromReplayPressure(start.Add(time.Duration(i) * blastRateFeedbackInterval))
	}

	if got, wantMin := controller.RateMbps(), 100; got < wantMin {
		t.Fatalf("RateMbps() after repeated high-ceiling replay pressure = %d, want >= %d", got, wantMin)
	}
}

func TestBlastRateControllerOpensInitialExplorationCeilingAfterCleanFeedback(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateControllerWithInitialLossCeiling(1200, 2250, 1200, start)

	sentBytes := uint64(0)
	receivedBytes := uint64(0)
	for i := 1; i <= 12; i++ {
		sentBytes += 15_000_000
		receivedBytes += 15_000_000
		packets := uint64(i) * 11_000
		controller.Observe(start.Add(time.Duration(i)*blastRateFeedbackInterval), blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      packets,
			MaxSeqPlusOne:        packets,
		})
	}

	if got, wantAbove := controller.RateMbps(), 1200; got <= wantAbove {
		t.Fatalf("RateMbps() after clean exploration feedback = %d, want above %d", got, wantAbove)
	}
	if got, wantMax := controller.RateMbps(), 2250; got > wantMax {
		t.Fatalf("RateMbps() after clean exploration feedback = %d, want <= %d", got, wantMax)
	}
}

func TestBlastRateControllerInitialHighExplorationCeilingReopensMateriallyAfterCleanFeedback(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateControllerWithInitialLossCeiling(1200, 2250, 1200, start)

	sentBytes := uint64(0)
	receivedBytes := uint64(0)
	for i := 1; i <= blastRateMediumLossCeilingProbeClean; i++ {
		sentBytes += 25_000_000
		receivedBytes += 25_000_000
		packets := uint64(i) * 18_000
		controller.Observe(start.Add(blastRateHighCeilingInitialHold+time.Duration(i)*blastRateFeedbackInterval), blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      packets,
			MaxSeqPlusOne:        packets,
		})
	}

	got := controller.RateMbps()
	if wantMin := 1500; got < wantMin {
		t.Fatalf("RateMbps() after initial high-ceiling clean reopen = %d, want >= %d", got, wantMin)
	}
	if wantMax := 1800; got > wantMax {
		t.Fatalf("RateMbps() after initial high-ceiling clean reopen = %d, want <= %d", got, wantMax)
	}
}

func TestBlastRateControllerRepairPressureDisablesFastInitialExplorationReopen(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControlWithInitialLossCeiling(1200, 2250, 1200, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(repairAt, control.repairPressurePackets())
	backedOff := control.RateMbps()

	sentBytes := uint64(180_000_000)
	receivedBytes := uint64(180_000_000)
	for i := 1; i <= blastRateMediumLossCeilingProbeClean; i++ {
		sentBytes += 15_000_000
		receivedBytes += 15_000_000
		packets := uint64(132_000 + i*11_000)
		control.controller.Observe(repairAt.Add(blastRateHoldAfterPressureDecrease+time.Duration(i)*blastRateFeedbackInterval), blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      packets,
			MaxSeqPlusOne:        packets,
		})
	}

	if got := control.RateMbps(); got > backedOff {
		t.Fatalf("RateMbps() after only fast-reopen clean samples following repair pressure = %d, want <= backed-off rate %d", got, backedOff)
	}
}

func TestBlastRateControllerKeepsInitialExplorationCeilingAcrossSingleLossBurst(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateControllerWithInitialLossCeiling(700, 2100, 1200, start)

	samples := []blastRateFeedback{
		{SentPayloadBytes: 51_806_208, ReceivedPayloadBytes: 47_562_976, ReceivedPackets: 35_005, MaxSeqPlusOne: 35_005},
		{SentPayloadBytes: 61_112_320, ReceivedPayloadBytes: 56_784_624, ReceivedPackets: 41_749, MaxSeqPlusOne: 41_749},
		{SentPayloadBytes: 73_891_840, ReceivedPayloadBytes: 67_659_448, ReceivedPackets: 50_441, MaxSeqPlusOne: 50_441},
		{SentPayloadBytes: 85_917_696, ReceivedPayloadBytes: 76_124_216, ReceivedPackets: 57_508, MaxSeqPlusOne: 57_508},
		{SentPayloadBytes: 102_203_392, ReceivedPayloadBytes: 86_068_144, ReceivedPackets: 65_547, MaxSeqPlusOne: 65_547},
	}
	for i, sample := range samples {
		controller.Observe(start.Add(blastRateHighCeilingInitialHold+time.Duration(i+1)*blastRateFeedbackInterval), sample)
	}
	if got := controller.RateMbps(); got != 1179 {
		t.Fatalf("RateMbps() before loss burst = %d, want 1179", got)
	}

	controller.Observe(start.Add(blastRateHighCeilingInitialHold+time.Duration(len(samples)+1)*blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     117_735_424,
		ReceivedPayloadBytes: 94_530_592,
		ReceivedPackets:      72_420,
		MaxSeqPlusOne:        73_288,
	})

	if got := controller.RateMbps(); got != 790 {
		t.Fatalf("RateMbps() after loss burst = %d, want 790", got)
	}
	if got := controller.effectiveCeilingMbps(); got != 1200 {
		t.Fatalf("effectiveCeilingMbps() after loss burst = %d, want 1200", got)
	}
	if !controller.initialLossCeiling {
		t.Fatal("initialLossCeiling = false, want true while still bounded by the probe-validated ceiling")
	}
}

func TestBlastRateControllerHighCeilingRampsCleanFeedbackWithinTwoSeconds(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(700, 2250, start)

	sentBytes := uint64(0)
	receivedBytes := uint64(0)
	for i := 1; i <= 15; i++ {
		sentBytes += 25_000_000
		receivedBytes += 25_000_000
		packets := uint64(i) * 18_000
		controller.Observe(start.Add(time.Duration(i)*blastRateFeedbackInterval), blastRateFeedback{
			SentPayloadBytes:     sentBytes,
			ReceivedPayloadBytes: receivedBytes,
			ReceivedPackets:      packets,
			MaxSeqPlusOne:        packets,
		})
	}

	if got, wantMin := controller.RateMbps(), 2000; got < wantMin {
		t.Fatalf("RateMbps() after high-ceiling clean ramp = %d, want >= %d", got, wantMin)
	}
}

func TestBlastSendControlHighCeilingResumesProbingSoonAfterRepairPressure(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(1109, 2487, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(repairAt, control.repairPressurePackets())
	backedOff := control.RateMbps()
	if backedOff >= 1109 {
		t.Fatalf("RateMbps() after repair pressure = %d, want below 1109", backedOff)
	}

	control.controller.Observe(repairAt.Add(time.Second), blastRateFeedback{
		SentPayloadBytes:     400_000_000,
		ReceivedPayloadBytes: 400_000_000,
		ReceivedPackets:      293_000,
		MaxSeqPlusOne:        293_000,
	})

	if got := control.RateMbps(); got <= backedOff {
		t.Fatalf("RateMbps() one second after high-ceiling repair pressure = %d, want above backed-off rate %d", got, backedOff)
	}
}

func TestBlastSendControlBacksOffMediumCeilingOnFullKnownGapRepairBatch(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(672, 700, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(repairAt, maxRepairRequestSeqs)

	if got := control.RateMbps(); got >= 672 {
		t.Fatalf("RateMbps() after full known-gap repair batch = %d, want backoff below 672", got)
	}
}

func TestBlastSendControlTreatsOneRepairBatchAtConservativeFloorAsTransient(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(350, 700, start)

	repairAt := start.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval)
	control.ObserveRepairPressure(repairAt, maxRepairRequestSeqs)

	if got := control.RateMbps(); got != 350 {
		t.Fatalf("RateMbps() after one floor-rate repair batch = %d, want 350", got)
	}

	control.ObserveRepairPressure(repairAt.Add(blastRateFeedbackInterval), maxRepairRequestSeqs)
	if got := control.RateMbps(); got >= 350 {
		t.Fatalf("RateMbps() after repeated floor-rate repair batches = %d, want backoff below 350", got)
	}
}

func TestBlastSendControlRepairPressureCapsLossCeilingBelowProbeCeiling(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(408, 700, start)

	control.ObserveRepairPressure(start.Add(blastRateHoldAfterDecrease+blastRateFeedbackInterval), blastRateRepairPressurePackets(control.RateMbps()))

	if got, wantMax := control.controller.effectiveCeilingMbps(), 367; got > wantMax {
		t.Fatalf("effectiveCeilingMbps() = %d, want repair pressure to cap ceiling <= %d", got, wantMax)
	}
}

func TestBlastSendControlRepairPressureUsesConservativeCeiling(t *testing.T) {
	start := time.Unix(0, 0)
	control := newBlastSendControl(350, 700, start)

	control.ObserveRepairPressure(start.Add(blastRateHoldAfterDecrease+blastRateFeedbackInterval), blastRateRepairPressurePackets(control.RateMbps()))

	if got, wantMax := control.controller.effectiveCeilingMbps(), 280; got > wantMax {
		t.Fatalf("effectiveCeilingMbps() = %d, want repair pressure ceiling <= %d", got, wantMax)
	}
}

func TestBlastRateControllerHoldsLowPathAfterLossForAtLeastOneSecond(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(84, 10_000, start)

	lossAt := start.Add(blastRateFeedbackInterval)
	controller.Observe(lossAt, blastRateFeedback{
		SentPayloadBytes:     10_000_000,
		ReceivedPayloadBytes: 8_000_000,
		ReceivedPackets:      800,
		MaxSeqPlusOne:        1000,
	})
	backedOff := controller.RateMbps()

	controller.Observe(lossAt.Add(time.Second), blastRateFeedback{
		SentPayloadBytes:     20_000_000,
		ReceivedPayloadBytes: 18_000_000,
		ReceivedPackets:      1800,
		MaxSeqPlusOne:        1800,
	})
	if got := controller.RateMbps(); got != backedOff {
		t.Fatalf("RateMbps() during one-second hold = %d, want %d", got, backedOff)
	}
}

func TestBlastRateControllerDropsLowPathOvershootToConservativeMargin(t *testing.T) {
	start := time.Unix(0, 0)
	controller := newBlastRateController(84, 10_000, start)

	controller.Observe(start.Add(blastRateFeedbackInterval), blastRateFeedback{
		SentPayloadBytes:     10_000_000,
		ReceivedPayloadBytes: 8_000_000,
		ReceivedPackets:      800,
		MaxSeqPlusOne:        1000,
	})

	if got := controller.RateMbps(); got > 56 {
		t.Fatalf("RateMbps() = %d, want low-path overshoot to drop to <= 56 Mbps", got)
	}
}

func TestBlastPacerKeepsVirtualScheduleAcrossSmallTimerOversleeps(t *testing.T) {
	start := time.Unix(0, 0)
	pacer := newBlastPacer(start)

	if got, want := pacer.schedule(start, 1_000_000, 80), 100*time.Millisecond; got != want {
		t.Fatalf("first sleep = %v, want %v", got, want)
	}
	if got, want := pacer.schedule(start.Add(120*time.Millisecond), 1_000_000, 80), 80*time.Millisecond; got != want {
		t.Fatalf("catch-up sleep = %v, want %v", got, want)
	}
}

func TestBlastPacerResetsVirtualScheduleWhenFarBehind(t *testing.T) {
	start := time.Unix(0, 0)
	pacer := newBlastPacer(start)
	_ = pacer.schedule(start, 1_000_000, 80)

	if got, want := pacer.schedule(start.Add(2*time.Second), 1_000_000, 80), 100*time.Millisecond; got != want {
		t.Fatalf("sleep after large stall = %v, want reset to %v", got, want)
	}
}
