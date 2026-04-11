package probe

import "math"

type SeriesSummary struct {
	RunCount            int     `json:"run_count"`
	SuccessCount        int     `json:"success_count"`
	FailureCount        int     `json:"failure_count"`
	FailureRate         float64 `json:"failure_rate"`
	AverageGoodputMbps  float64 `json:"average_goodput_mbps"`
	PeakGoodputMbps     float64 `json:"peak_goodput_mbps"`
	AverageWallTimeMS   float64 `json:"average_wall_time_ms"`
	FirstByteCount      int     `json:"first_byte_count"`
	AverageFirstByteMS  float64 `json:"average_first_byte_ms"`
	PeakFirstByteMS     int64   `json:"peak_first_byte_ms"`
	HasFirstByteMetrics bool    `json:"has_first_byte_metrics"`
}

type RegressionResult struct {
	Base SeriesSummary `json:"base"`
	Head SeriesSummary `json:"head"`

	WallTimeRegression    bool     `json:"wall_time_regression"`
	FailureRateRegression bool     `json:"failure_rate_regression"`
	IsRegression          bool     `json:"is_regression"`
	WallTimeDeltaMS       float64  `json:"wall_time_delta_ms,omitempty"`
	FailureRateDelta      float64  `json:"failure_rate_delta,omitempty"`
	Reasons               []string `json:"reasons,omitempty"`
}

func SummarizeRuns(runs []RunReport) SeriesSummary {
	var summary SeriesSummary
	if len(runs) == 0 {
		return summary
	}

	var totalGoodput float64
	var totalWallTime float64
	var peakGoodput float64
	var firstByteTotal float64
	var peakFirstByte int64

	for _, run := range runs {
		summary.RunCount++
		if isRunSuccessful(run) {
			summary.SuccessCount++
		} else {
			summary.FailureCount++
		}

		totalGoodput += run.GoodputMbps
		totalWallTime += float64(run.DurationMS)
		if runPeak := runPeakGoodput(run); runPeak > peakGoodput {
			peakGoodput = runPeak
		}

		if hasMeasuredFirstByte(run) {
			summary.FirstByteCount++
			firstByteTotal += float64(run.FirstByteMS)
			if run.FirstByteMS > peakFirstByte {
				peakFirstByte = run.FirstByteMS
			}
		}
	}

	summary.FailureRate = float64(summary.FailureCount) / float64(summary.RunCount)
	summary.AverageGoodputMbps = totalGoodput / float64(summary.RunCount)
	summary.PeakGoodputMbps = peakGoodput
	summary.AverageWallTimeMS = totalWallTime / float64(summary.RunCount)
	if summary.FirstByteCount > 0 {
		summary.AverageFirstByteMS = firstByteTotal / float64(summary.FirstByteCount)
		summary.PeakFirstByteMS = peakFirstByte
		summary.HasFirstByteMetrics = true
	}
	return summary
}

func CompareSummaries(base, head SeriesSummary) RegressionResult {
	result := RegressionResult{
		Base: base,
		Head: head,
	}
	if base.RunCount == 0 || head.RunCount == 0 {
		return result
	}

	if head.AverageWallTimeMS > base.AverageWallTimeMS {
		result.WallTimeRegression = true
		result.WallTimeDeltaMS = head.AverageWallTimeMS - base.AverageWallTimeMS
		result.Reasons = append(result.Reasons, "average wall time increased")
	}
	if head.FailureRate > base.FailureRate {
		result.FailureRateRegression = true
		result.FailureRateDelta = head.FailureRate - base.FailureRate
		result.Reasons = append(result.Reasons, "failure rate increased")
	}
	result.IsRegression = result.WallTimeRegression || result.FailureRateRegression
	return result
}

func runPeakGoodput(run RunReport) float64 {
	if run.PeakGoodputMbps > 0 {
		return run.PeakGoodputMbps
	}
	return math.Max(run.GoodputMbps, 0)
}

func isRunSuccessful(run RunReport) bool {
	if run.Error != "" {
		return false
	}
	if run.Success != nil {
		return *run.Success
	}
	// Preserve legacy zero-value RunReport behavior.
	return true
}

func hasMeasuredFirstByte(run RunReport) bool {
	if !isRunSuccessful(run) {
		return false
	}
	if run.Success != nil {
		return true
	}
	return run.FirstByteMS > 0
}
