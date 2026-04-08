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
	for i := 1; i <= 12; i++ {
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
