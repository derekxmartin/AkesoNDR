package common

import "time"

// HostScore represents the aggregated threat score for a single host,
// inspired by Vectra's threat + certainty model (Section 3.6).
type HostScore struct {
	// Identity
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`

	// Scores (0-100)
	ThreatScore    int `json:"threat_score"`
	CertaintyScore int `json:"certainty_score"`

	// Classification
	Quadrant Quadrant `json:"quadrant"`

	// Detection summary
	ActiveDetections     int      `json:"active_detections"`
	DetectionTypes       []string `json:"detection_types,omitempty"`
	MITRETacticsObserved []string `json:"mitre_tactics_observed,omitempty"`

	// History
	ScoreHistory []ScoreSnapshot `json:"score_history,omitempty"`

	// Timing
	FirstSeen   time.Time `json:"first_seen"`
	LastUpdated time.Time `json:"last_updated"`
}

// ScoreSnapshot captures a point-in-time score for trend analysis.
type ScoreSnapshot struct {
	Timestamp      time.Time `json:"timestamp"`
	ThreatScore    int       `json:"threat_score"`
	CertaintyScore int       `json:"certainty_score"`
}

// ComputeQuadrant derives the quadrant from threat and certainty scores.
// Thresholds: Low <25, Medium 25-49, High 50-74, Critical ≥75.
func ComputeQuadrant(threat, certainty int) Quadrant {
	combined := (threat + certainty) / 2
	switch {
	case combined >= 75:
		return QuadrantCritical
	case combined >= 50:
		return QuadrantHigh
	case combined >= 25:
		return QuadrantMedium
	default:
		return QuadrantLow
	}
}
