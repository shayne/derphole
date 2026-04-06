package probe

import (
	"encoding/json"
	"fmt"
)

type RunReport struct {
	Host          string   `json:"host"`
	User          string   `json:"user,omitempty"`
	RemotePath    string   `json:"remote_path,omitempty"`
	Mode          string   `json:"mode"`
	Direction     string   `json:"direction"`
	SizeBytes     int64    `json:"size_bytes"`
	DurationMS    int64    `json:"duration_ms"`
	GoodputMbps   float64  `json:"goodput_mbps"`
	Direct        bool     `json:"direct"`
	FirstByteMS   int64    `json:"first_byte_ms"`
	LossRate      float64  `json:"loss_rate"`
	Retransmits   int64    `json:"retransmits"`
	ListenAddr    string   `json:"listen_addr,omitempty"`
	ServerCommand []string `json:"server_command,omitempty"`
	ClientCommand []string `json:"client_command,omitempty"`
}

func (r RunReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r RunReport) Markdown() string {
	return fmt.Sprintf(
		"host=%s mode=%s direction=%s size_bytes=%d duration_ms=%d goodput_mbps=%.1f direct=%t",
		r.Host,
		r.Mode,
		r.Direction,
		r.SizeBytes,
		r.DurationMS,
		r.GoodputMbps,
		r.Direct,
	)
}
