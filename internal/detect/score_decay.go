// Package detect — score_decay.go implements time-based score decay
// for the host scoring engine.
//
// Detections lose relevance over time. A detection from 1 hour ago
// should contribute more to a host's score than one from 24 hours ago.
// The decay function uses exponential decay with a configurable half-life.
package detect

import (
	"math"
	"time"
)

// DefaultHalfLife is the default score half-life: 12 hours.
// After 12 hours, a detection's contribution is halved.
const DefaultHalfLife = 12 * time.Hour

// DecayFactor computes the exponential decay multiplier for a detection
// based on its age. Returns a value in (0, 1] where 1.0 = just now,
// 0.5 = one half-life ago, 0.25 = two half-lives ago, etc.
//
//	factor = 2^(-age/halfLife)
func DecayFactor(detectionTime time.Time, now time.Time, halfLife time.Duration) float64 {
	if halfLife <= 0 {
		halfLife = DefaultHalfLife
	}

	age := now.Sub(detectionTime)
	if age <= 0 {
		return 1.0
	}

	// Exponential decay: factor = 2^(-age/halfLife)
	exponent := -float64(age) / float64(halfLife)
	factor := math.Pow(2, exponent)

	// Clamp to minimum contribution (don't let old detections vanish entirely
	// within a reasonable window — floor at 1%).
	if factor < 0.01 {
		return 0.01
	}
	return factor
}

// DecayedScore applies decay to a raw score based on detection age.
func DecayedScore(rawScore int, detectionTime time.Time, now time.Time, halfLife time.Duration) float64 {
	return float64(rawScore) * DecayFactor(detectionTime, now, halfLife)
}

// IsExpired returns true if a detection is old enough to be removed
// from active scoring entirely. Default expiration: 7 half-lives
// (~3.5 days at 12h half-life), at which point contribution is <1%.
func IsExpired(detectionTime time.Time, now time.Time, halfLife time.Duration) bool {
	if halfLife <= 0 {
		halfLife = DefaultHalfLife
	}
	return now.Sub(detectionTime) > 7*halfLife
}
