package probe

import (
	"encoding/json"
	"fmt"
)

type RunReport struct {
	Host          string        `json:"host"`
	Mode          string        `json:"mode"`
	Transport     string        `json:"transport,omitempty"`
	Direction     string        `json:"direction"`
	SizeBytes     int64         `json:"size_bytes"`
	BytesReceived int64         `json:"bytes_received"`
	DurationMS    int64         `json:"duration_ms"`
	GoodputMbps   float64       `json:"goodput_mbps"`
	Direct        bool          `json:"direct"`
	FirstByteMS   int64         `json:"first_byte_ms"`
	LossRate      float64       `json:"loss_rate"`
	Retransmits   int64         `json:"retransmits"`
	Local         TransportCaps `json:"local,omitempty"`
	Remote        TransportCaps `json:"remote,omitempty"`
}

func (r RunReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
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
