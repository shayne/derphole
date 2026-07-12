// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	externalV2BulkPacketIPv4HeaderBytes = 20
	externalV2BulkPacketUDPHeaderBytes  = 8

	externalV2BulkPacketInitialWireMbpsEnv           = "DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS"
	externalV2BulkPacketDefaultInitialWireMbps       = 1000
	externalV2BulkPacketCeilingWireMbps              = 2400
	externalV2BulkPacketMinimumWireMbps              = 128
	externalV2BulkPacketIncreaseWireMbps             = 64
	externalV2BulkPacketBackoffNumerator             = 85
	externalV2BulkPacketBackoffDenominator           = 100
	externalV2BulkPacketPaceBurstBytes               = 64 << 10
	externalV2BulkPacketMinimumSampleWire            = 8 << 20
	externalV2BulkPacketSoftRepairPPM          int64 = 20_000
	externalV2BulkPacketHardRepairPPM          int64 = 80_000
	externalV2BulkPacketHealthyPPM             int64 = 900_000
	externalV2BulkPacketControllerCooldown           = 4
	externalV2BulkPacketPressureWindows              = 2

	externalV2BulkPacketControllerInterval = 500 * time.Millisecond
)

type externalV2BulkPacketControllerSample struct {
	At                    time.Time
	PrimaryWireBytes      int64
	RepairWireBytes       int64
	PeerBytes             int64
	PeerTransferElapsedMS int64
	PeerProgress          bool
}

type externalV2BulkPacketControllerDecision struct {
	TargetMbps        int
	Action            string
	Reason            string
	DeliveredWireMbps int
	RepairPPM         int64
}

type externalV2BulkPacketController struct {
	targetMbps      int
	cooldown        int
	previous        externalV2BulkPacketControllerSample
	lastObserved    externalV2BulkPacketControllerSample
	haveSample      bool
	pressureWindows int
}

func externalV2BulkPacketInitialWireMbps() int {
	raw := strings.TrimSpace(os.Getenv(externalV2BulkPacketInitialWireMbpsEnv))
	if raw == "" {
		return externalV2BulkPacketDefaultInitialWireMbps
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < externalV2BulkPacketMinimumWireMbps || value > externalV2BulkPacketCeilingWireMbps {
		return externalV2BulkPacketDefaultInitialWireMbps
	}
	return value
}

func newExternalV2BulkPacketController(initialMbps int) *externalV2BulkPacketController {
	return &externalV2BulkPacketController{targetMbps: initialMbps}
}

func externalV2BulkPacketIPv4WireBytes(datagramBytes int) int {
	if datagramBytes <= 0 {
		return 0
	}
	return datagramBytes +
		externalV2BulkPacketIPv4HeaderBytes +
		externalV2BulkPacketUDPHeaderBytes
}

func (c *externalV2BulkPacketController) Observe(
	sample externalV2BulkPacketControllerSample,
) externalV2BulkPacketControllerDecision {
	if !c.haveSample {
		c.previous = sample
		c.lastObserved = sample
		c.haveSample = true
		return c.decision("hold", "initial-target", 0, 0)
	}
	if c.hasCounterReset(sample) {
		c.previous = sample
		c.lastObserved = sample
		c.pressureWindows = 0
		return c.decision("hold", "counter-reset", 0, 0)
	}
	c.lastObserved = sample

	primaryDelta := sample.PrimaryWireBytes - c.previous.PrimaryWireBytes
	repairDelta := sample.RepairWireBytes - c.previous.RepairWireBytes
	deliveredWireMbps, peerReady := c.deliveredWireRate(sample)
	if primaryDelta < externalV2BulkPacketMinimumSampleWire {
		return c.decision("hold", "insufficient-wire-sample", deliveredWireMbps, 0)
	}
	c.previous = sample

	return c.decideSample(primaryDelta, repairDelta, deliveredWireMbps, peerReady)
}

func (c *externalV2BulkPacketController) hasCounterReset(
	sample externalV2BulkPacketControllerSample,
) bool {
	if sample.PrimaryWireBytes < c.lastObserved.PrimaryWireBytes {
		return true
	}
	if sample.RepairWireBytes < c.lastObserved.RepairWireBytes {
		return true
	}
	if !sample.PeerProgress || !c.lastObserved.PeerProgress {
		return false
	}
	return sample.PeerBytes < c.lastObserved.PeerBytes ||
		sample.PeerTransferElapsedMS < c.lastObserved.PeerTransferElapsedMS
}

func (c *externalV2BulkPacketController) deliveredWireRate(
	sample externalV2BulkPacketControllerSample,
) (int, bool) {
	if !sample.PeerProgress ||
		!c.previous.PeerProgress ||
		sample.PeerTransferElapsedMS <= c.previous.PeerTransferElapsedMS {
		return 0, false
	}
	peerBytesDelta := sample.PeerBytes - c.previous.PeerBytes
	peerElapsedDelta := sample.PeerTransferElapsedMS - c.previous.PeerTransferElapsedMS
	return externalV2BulkPacketDeliveredWireMbps(peerBytesDelta, peerElapsedDelta), true
}

func (c *externalV2BulkPacketController) decideSample(
	primaryDelta int64,
	repairDelta int64,
	deliveredWireMbps int,
	peerReady bool,
) externalV2BulkPacketControllerDecision {
	totalDelta := primaryDelta + repairDelta
	repairPPM := externalV2BulkPacketRepairPPM(repairDelta, totalDelta)
	if !peerReady {
		c.pressureWindows = 0
		return c.decision("hold", "awaiting-peer-progress", 0, repairPPM)
	}
	return c.decideWithPeerProgress(deliveredWireMbps, repairPPM)
}

func (c *externalV2BulkPacketController) decideWithPeerProgress(
	deliveredWireMbps int,
	repairPPM int64,
) externalV2BulkPacketControllerDecision {
	healthyDelivery := int64(deliveredWireMbps)*1_000_000 >=
		int64(c.targetMbps)*externalV2BulkPacketHealthyPPM
	if repairPPM >= externalV2BulkPacketSoftRepairPPM && !healthyDelivery {
		return c.confirmRepairPressure(deliveredWireMbps, repairPPM)
	}
	c.pressureWindows = 0
	if repairPPM >= externalV2BulkPacketSoftRepairPPM {
		if c.cooldown > 0 {
			c.cooldown--
		}
		return c.decision("hold", "repair-hold", deliveredWireMbps, repairPPM)
	}
	if c.cooldown > 0 {
		c.cooldown--
		return c.decision("hold", "backoff-cooldown", deliveredWireMbps, repairPPM)
	}
	if !healthyDelivery {
		return c.decision("hold", "receiver-limited", deliveredWireMbps, repairPPM)
	}
	if c.targetMbps >= externalV2BulkPacketCeilingWireMbps {
		return c.decision("hold", "ceiling", deliveredWireMbps, repairPPM)
	}
	c.targetMbps = min(
		externalV2BulkPacketCeilingWireMbps,
		c.targetMbps+externalV2BulkPacketIncreaseWireMbps,
	)
	return c.decision("increase", "clean-delivery", deliveredWireMbps, repairPPM)
}

func (c *externalV2BulkPacketController) confirmRepairPressure(
	deliveredWireMbps int,
	repairPPM int64,
) externalV2BulkPacketControllerDecision {
	c.pressureWindows++
	if c.pressureWindows < externalV2BulkPacketPressureWindows {
		return c.decision("hold", "repair-pressure-pending", deliveredWireMbps, repairPPM)
	}
	reason := "repair-and-delivery-drop"
	if repairPPM >= externalV2BulkPacketHardRepairPPM {
		reason = "hard-repair-pressure"
	}
	return c.decrease(reason, deliveredWireMbps, repairPPM)
}

func (c *externalV2BulkPacketController) decrease(
	reason string,
	deliveredWireMbps int,
	repairPPM int64,
) externalV2BulkPacketControllerDecision {
	c.pressureWindows = 0
	next := c.targetMbps *
		externalV2BulkPacketBackoffNumerator /
		externalV2BulkPacketBackoffDenominator
	next = max(externalV2BulkPacketMinimumWireMbps, next)
	if next >= c.targetMbps {
		return c.decision("hold", "minimum", deliveredWireMbps, repairPPM)
	}
	c.targetMbps = next
	c.cooldown = externalV2BulkPacketControllerCooldown
	return c.decision("decrease", reason, deliveredWireMbps, repairPPM)
}

func (c *externalV2BulkPacketController) decision(
	action string,
	reason string,
	deliveredWireMbps int,
	repairPPM int64,
) externalV2BulkPacketControllerDecision {
	return externalV2BulkPacketControllerDecision{
		TargetMbps:        c.targetMbps,
		Action:            action,
		Reason:            reason,
		DeliveredWireMbps: deliveredWireMbps,
		RepairPPM:         repairPPM,
	}
}

func externalV2BulkPacketDeliveredWireMbps(peerBytes int64, elapsedMS int64) int {
	if peerBytes <= 0 || elapsedMS <= 0 {
		return 0
	}
	wireBits := int64(8 * (externalV2BulkPacketPayloadSize +
		externalV2BulkPacketHeaderSize +
		16 +
		externalV2BulkPacketIPv4HeaderBytes +
		externalV2BulkPacketUDPHeaderBytes))
	payloadMillis := int64(1000 * externalV2BulkPacketPayloadSize)

	var wireMbps int64
	if peerBytes <= math.MaxInt64/wireBits &&
		elapsedMS <= math.MaxInt64/payloadMillis {
		wireMbps = peerBytes * wireBits / (elapsedMS * payloadMillis)
	} else {
		var numerator big.Int
		numerator.Mul(big.NewInt(peerBytes), big.NewInt(wireBits))
		var denominator big.Int
		denominator.Mul(big.NewInt(elapsedMS), big.NewInt(payloadMillis))
		numerator.Quo(&numerator, &denominator)
		if !numerator.IsInt64() {
			return math.MaxInt
		}
		wireMbps = numerator.Int64()
	}
	if wireMbps > int64(math.MaxInt) {
		return math.MaxInt
	}
	return int(wireMbps)
}

func externalV2BulkPacketRepairPPM(repairBytes int64, totalBytes int64) int64 {
	if repairBytes <= 0 || totalBytes <= 0 {
		return 0
	}
	return repairBytes * 1_000_000 / totalBytes
}
