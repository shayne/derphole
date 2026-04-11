package probe

import (
	"encoding/json"
	"fmt"
)

type RunReport struct {
	Host            string        `json:"host"`
	Mode            string        `json:"mode"`
	Transport       string        `json:"transport,omitempty"`
	Direction       string        `json:"direction"`
	SizeBytes       int64         `json:"size_bytes"`
	BytesReceived   int64         `json:"bytes_received"`
	DurationMS      int64         `json:"duration_ms"`
	GoodputMbps     float64       `json:"goodput_mbps"`
	PeakGoodputMbps float64       `json:"peak_goodput_mbps,omitempty"`
	Direct          bool          `json:"direct"`
	FirstByteMS     int64         `json:"first_byte_ms"`
	LossRate        float64       `json:"loss_rate"`
	Retransmits     int64         `json:"retransmits"`
	Success         bool          `json:"success"`
	Error           string        `json:"error,omitempty"`
	Local           TransportCaps `json:"local,omitempty"`
	Remote          TransportCaps `json:"remote,omitempty"`
	successSet      bool          `json:"-"`
}

func (r RunReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r RunReport) MarshalJSON() ([]byte, error) {
	type runReportJSON struct {
		Host            string        `json:"host"`
		Mode            string        `json:"mode"`
		Transport       string        `json:"transport,omitempty"`
		Direction       string        `json:"direction"`
		SizeBytes       int64         `json:"size_bytes"`
		BytesReceived   int64         `json:"bytes_received"`
		DurationMS      int64         `json:"duration_ms"`
		GoodputMbps     float64       `json:"goodput_mbps"`
		PeakGoodputMbps float64       `json:"peak_goodput_mbps,omitempty"`
		Direct          bool          `json:"direct"`
		FirstByteMS     int64         `json:"first_byte_ms"`
		LossRate        float64       `json:"loss_rate"`
		Retransmits     int64         `json:"retransmits"`
		Success         *bool         `json:"success,omitempty"`
		Error           string        `json:"error,omitempty"`
		Local           TransportCaps `json:"local,omitempty"`
		Remote          TransportCaps `json:"remote,omitempty"`
	}

	var success *bool
	if r.successSet || r.Success {
		v := r.Success
		success = &v
	}
	return json.MarshalIndent(runReportJSON{
		Host:            r.Host,
		Mode:            r.Mode,
		Transport:       r.Transport,
		Direction:       r.Direction,
		SizeBytes:       r.SizeBytes,
		BytesReceived:   r.BytesReceived,
		DurationMS:      r.DurationMS,
		GoodputMbps:     r.GoodputMbps,
		PeakGoodputMbps: r.PeakGoodputMbps,
		Direct:          r.Direct,
		FirstByteMS:     r.FirstByteMS,
		LossRate:        r.LossRate,
		Retransmits:     r.Retransmits,
		Success:         success,
		Error:           r.Error,
		Local:           r.Local,
		Remote:          r.Remote,
	}, "", "  ")
}

func (r *RunReport) UnmarshalJSON(data []byte) error {
	type runReportJSON struct {
		Host            string        `json:"host"`
		Mode            string        `json:"mode"`
		Transport       string        `json:"transport,omitempty"`
		Direction       string        `json:"direction"`
		SizeBytes       int64         `json:"size_bytes"`
		BytesReceived   int64         `json:"bytes_received"`
		DurationMS      int64         `json:"duration_ms"`
		GoodputMbps     float64       `json:"goodput_mbps"`
		PeakGoodputMbps float64       `json:"peak_goodput_mbps,omitempty"`
		Direct          bool          `json:"direct"`
		FirstByteMS     int64         `json:"first_byte_ms"`
		LossRate        float64       `json:"loss_rate"`
		Retransmits     int64         `json:"retransmits"`
		Success         *bool         `json:"success,omitempty"`
		Error           string        `json:"error,omitempty"`
		Local           TransportCaps `json:"local,omitempty"`
		Remote          TransportCaps `json:"remote,omitempty"`
	}

	var decoded runReportJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = RunReport{
		Host:            decoded.Host,
		Mode:            decoded.Mode,
		Transport:       decoded.Transport,
		Direction:       decoded.Direction,
		SizeBytes:       decoded.SizeBytes,
		BytesReceived:   decoded.BytesReceived,
		DurationMS:      decoded.DurationMS,
		GoodputMbps:     decoded.GoodputMbps,
		PeakGoodputMbps: decoded.PeakGoodputMbps,
		Direct:          decoded.Direct,
		FirstByteMS:     decoded.FirstByteMS,
		LossRate:        decoded.LossRate,
		Retransmits:     decoded.Retransmits,
		Error:           decoded.Error,
		Local:           decoded.Local,
		Remote:          decoded.Remote,
	}
	if decoded.Success != nil {
		r.Success = *decoded.Success
		r.successSet = true
	}
	return nil
}

func (r RunReport) Markdown() string {
	return fmt.Sprintf(
		"- host=%s mode=%s transport=%s direction=%s size=%d bytes_received=%d duration_ms=%d goodput_mbps=%.1f direct=%t first_byte_ms=%d loss_rate=%.4f retransmits=%d local=%s remote=%s",
		r.Host,
		r.Mode,
		r.Transport,
		r.Direction,
		r.SizeBytes,
		r.BytesReceived,
		r.DurationMS,
		r.GoodputMbps,
		r.Direct,
		r.FirstByteMS,
		r.LossRate,
		r.Retransmits,
		r.Local.Summary(),
		r.Remote.Summary(),
	)
}
