// Package detect — quadrant.go implements the Vectra-inspired host
// quadrant classification for the threat × certainty scoring model.
//
// Hosts are mapped to quadrants based on their combined threat and
// certainty scores. The quadrant boundaries are configurable but
// default to: Critical = both > 70, High = either > 50, Medium =
// either > 25, Low = both ≤ 25.
package detect

import "github.com/akesondr/akeso-ndr/internal/common"

// QuadrantConfig holds configurable thresholds for quadrant classification.
type QuadrantConfig struct {
	CriticalThreshold int // Both threat AND certainty must exceed this. Default: 70.
	HighThreshold     int // Either threat OR certainty exceeds this. Default: 50.
	MediumThreshold   int // Either threat OR certainty exceeds this. Default: 25.
}

// DefaultQuadrantConfig returns the default quadrant thresholds.
func DefaultQuadrantConfig() QuadrantConfig {
	return QuadrantConfig{
		CriticalThreshold: 70,
		HighThreshold:     50,
		MediumThreshold:   25,
	}
}

// ClassifyQuadrant maps threat × certainty scores to a quadrant.
// This uses the "both must be high" model for Critical (high confidence
// of a real threat) vs the "combined average" model in common.ComputeQuadrant.
func ClassifyQuadrant(threat, certainty int, cfg QuadrantConfig) common.Quadrant {
	if cfg.CriticalThreshold <= 0 {
		cfg = DefaultQuadrantConfig()
	}

	// Critical: both threat AND certainty are above the critical threshold.
	if threat > cfg.CriticalThreshold && certainty > cfg.CriticalThreshold {
		return common.QuadrantCritical
	}

	// High: either score is above the high threshold AND the other is at least medium.
	if (threat > cfg.HighThreshold && certainty > cfg.MediumThreshold) ||
		(certainty > cfg.HighThreshold && threat > cfg.MediumThreshold) {
		return common.QuadrantHigh
	}

	// Medium: either score exceeds the medium threshold.
	if threat > cfg.MediumThreshold || certainty > cfg.MediumThreshold {
		return common.QuadrantMedium
	}

	return common.QuadrantLow
}
