// Package detect — host_scorer.go aggregates per-host detections into
// composite threat + certainty scores, inspired by Vectra's scoring model.
//
// Each detection contributes to a host's score based on:
//   - Detection severity and certainty
//   - MITRE ATT&CK tactic progression (multi-stage = higher score)
//   - Recency weighting (exponential decay with configurable half-life)
//   - Number of distinct detection types
//
// The scorer maintains a live view of all monitored hosts and their
// current quadrant classification (Low/Medium/High/Critical).
package detect

import (
	"log"
	"sync"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// HostScorer aggregates detections into per-host threat scores.
type HostScorer struct {
	mu       sync.RWMutex
	hosts    map[string]*scoredHost
	halfLife time.Duration
	quadCfg  QuadrantConfig

	// Maximum score history entries per host.
	maxHistory int
}

// scoredHost holds the internal state for a single host's score.
type scoredHost struct {
	ip         string
	hostname   string
	detections []*common.Detection
	firstSeen  time.Time
	lastUpdate time.Time
}

// NewHostScorer creates a host scorer with the given decay half-life.
func NewHostScorer(halfLife time.Duration, quadCfg QuadrantConfig) *HostScorer {
	if halfLife <= 0 {
		halfLife = DefaultHalfLife
	}
	if quadCfg.CriticalThreshold <= 0 {
		quadCfg = DefaultQuadrantConfig()
	}
	return &HostScorer{
		hosts:      make(map[string]*scoredHost),
		halfLife:   halfLife,
		quadCfg:    quadCfg,
		maxHistory: 24, // 24 snapshots
	}
}

// AddDetection records a new detection for the source host.
func (s *HostScorer) AddDetection(d *common.Detection) {
	if d.SrcIP == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	host, ok := s.hosts[d.SrcIP]
	if !ok {
		host = &scoredHost{
			ip:        d.SrcIP,
			firstSeen: d.Timestamp,
		}
		s.hosts[d.SrcIP] = host
	}

	host.detections = append(host.detections, d)
	host.lastUpdate = d.Timestamp

	log.Printf("[scorer] Detection added for %s: %s (severity=%d, certainty=%d)",
		d.SrcIP, d.Name, d.Severity, d.Certainty)
}

// GetHostScore computes the current score for a specific host.
func (s *HostScorer) GetHostScore(ip string) *common.HostScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	host, ok := s.hosts[ip]
	if !ok {
		return nil
	}

	return s.computeScore(host, time.Now())
}

// GetAllHostScores returns computed scores for all monitored hosts.
func (s *HostScorer) GetAllHostScores() []*common.HostScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var scores []*common.HostScore
	for _, host := range s.hosts {
		scores = append(scores, s.computeScore(host, now))
	}
	return scores
}

// Cleanup removes expired detections and empty hosts.
func (s *HostScorer) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for ip, host := range s.hosts {
		// Remove expired detections.
		var active []*common.Detection
		for _, d := range host.detections {
			if !IsExpired(d.Timestamp, now, s.halfLife) {
				active = append(active, d)
			}
		}
		host.detections = active

		// Remove empty hosts.
		if len(host.detections) == 0 {
			delete(s.hosts, ip)
		}
	}
}

// Stats returns the number of tracked hosts and total active detections.
func (s *HostScorer) Stats() (hosts int, detections int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, host := range s.hosts {
		hosts++
		detections += len(host.detections)
	}
	return
}

// ---------------------------------------------------------------------------
// Internal scoring
// ---------------------------------------------------------------------------

func (s *HostScorer) computeScore(host *scoredHost, now time.Time) *common.HostScore {
	if len(host.detections) == 0 {
		return &common.HostScore{
			IP:        host.ip,
			Hostname:  host.hostname,
			Quadrant:  common.QuadrantLow,
			FirstSeen: host.firstSeen,
		}
	}

	// Accumulate weighted threat and certainty from all active detections.
	var totalThreat, totalCertainty float64
	detectionTypes := make(map[string]bool)
	tacticIDs := make(map[string]bool)

	for _, d := range host.detections {
		decay := DecayFactor(d.Timestamp, now, s.halfLife)

		totalThreat += float64(d.Severity) * decay
		totalCertainty += float64(d.Certainty) * decay

		detectionTypes[string(d.Type)] = true
		if d.MITRE.TacticID != "" {
			tacticIDs[d.MITRE.TacticID] = true
		}
	}

	// Diversity bonus: more distinct detection types = higher confidence.
	diversityBonus := 1.0 + float64(len(detectionTypes)-1)*0.15
	if diversityBonus > 2.0 {
		diversityBonus = 2.0
	}

	// Tactic progression multiplier.
	var tactics []string
	for tid := range tacticIDs {
		tactics = append(tactics, tid)
	}
	progressionMult := TacticProgressionMultiplier(tactics)

	// Compute final scores (0-100 scale).
	// Base = sum of decayed severity/certainty, scaled by diversity and progression.
	threatScore := int(totalThreat * diversityBonus * progressionMult)
	certaintyScore := int(totalCertainty * diversityBonus)

	// Clamp to 0-100.
	if threatScore > 100 {
		threatScore = 100
	}
	if certaintyScore > 100 {
		certaintyScore = 100
	}

	// Build type and tactic lists.
	var typeList []string
	for t := range detectionTypes {
		typeList = append(typeList, t)
	}
	var tacticList []string
	for t := range tacticIDs {
		tacticList = append(tacticList, t)
	}

	return &common.HostScore{
		IP:                   host.ip,
		Hostname:             host.hostname,
		ThreatScore:          threatScore,
		CertaintyScore:       certaintyScore,
		Quadrant:             ClassifyQuadrant(threatScore, certaintyScore, s.quadCfg),
		ActiveDetections:     len(host.detections),
		DetectionTypes:       typeList,
		MITRETacticsObserved: tacticList,
		FirstSeen:            host.firstSeen,
		LastUpdated:          host.lastUpdate,
	}
}
