// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"encoding/json"
	"fmt"
)

type RunReport struct {
	Host              string        `json:"host"`
	Mode              string        `json:"mode"`
	Transport         string        `json:"transport,omitempty"`
	Direction         string        `json:"direction"`
	SizeBytes         int64         `json:"size_bytes"`
	BytesReceived     int64         `json:"bytes_received"`
	DurationMS        int64         `json:"duration_ms"`
	GoodputMbps       float64       `json:"goodput_mbps"`
	PeakGoodputMbps   float64       `json:"peak_goodput_mbps,omitempty"`
	Direct            bool          `json:"direct"`
	FirstByteMS       int64         `json:"first_byte_ms"`
	FirstByteMeasured *bool         `json:"first_byte_measured,omitempty"`
	LossRate          float64       `json:"loss_rate"`
	Retransmits       int64         `json:"retransmits"`
	Success           *bool         `json:"success,omitempty"`
	Error             string        `json:"error,omitempty"`
	Local             TransportCaps `json:"local,omitempty"`
	Remote            TransportCaps `json:"remote,omitempty"`
}

func (r RunReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r RunReport) MarshalJSON() ([]byte, error) {
	type runReportJSON struct {
		Host              string         `json:"host"`
		Mode              string         `json:"mode"`
		Transport         string         `json:"transport,omitempty"`
		Direction         string         `json:"direction"`
		SizeBytes         int64          `json:"size_bytes"`
		BytesReceived     int64          `json:"bytes_received"`
		DurationMS        int64          `json:"duration_ms"`
		GoodputMbps       float64        `json:"goodput_mbps"`
		PeakGoodputMbps   float64        `json:"peak_goodput_mbps,omitempty"`
		Direct            bool           `json:"direct"`
		FirstByteMS       int64          `json:"first_byte_ms"`
		FirstByteMeasured *bool          `json:"first_byte_measured,omitempty"`
		LossRate          float64        `json:"loss_rate"`
		Retransmits       int64          `json:"retransmits"`
		Success           *bool          `json:"success,omitempty"`
		Error             string         `json:"error,omitempty"`
		Local             *TransportCaps `json:"local,omitempty"`
		Remote            *TransportCaps `json:"remote,omitempty"`
	}

	var local *TransportCaps
	if !isZeroTransportCaps(r.Local) {
		local = &r.Local
	}
	var remote *TransportCaps
	if !isZeroTransportCaps(r.Remote) {
		remote = &r.Remote
	}

	return json.MarshalIndent(runReportJSON{
		Host:              r.Host,
		Mode:              r.Mode,
		Transport:         r.Transport,
		Direction:         r.Direction,
		SizeBytes:         r.SizeBytes,
		BytesReceived:     r.BytesReceived,
		DurationMS:        r.DurationMS,
		GoodputMbps:       r.GoodputMbps,
		PeakGoodputMbps:   r.PeakGoodputMbps,
		Direct:            r.Direct,
		FirstByteMS:       r.FirstByteMS,
		FirstByteMeasured: r.FirstByteMeasured,
		LossRate:          r.LossRate,
		Retransmits:       r.Retransmits,
		Success:           r.Success,
		Error:             r.Error,
		Local:             local,
		Remote:            remote,
	}, "", "  ")
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

func boolPtr(v bool) *bool {
	return &v
}

func isZeroTransportCaps(c TransportCaps) bool {
	return c == TransportCaps{}
}
