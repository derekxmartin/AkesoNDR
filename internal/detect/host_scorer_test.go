package detect

import (
	"testing"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// ---------------------------------------------------------------------------
// Host scorer tests (P6-T1)
// ---------------------------------------------------------------------------

func TestHostScorerBeaconPlusLateralHigherThanBeaconOnly(t *testing.T) {
	scorer := NewHostScorer(12*time.Hour, DefaultQuadrantConfig())

	// Host A: beacon only.
	scorer.AddDetection(&common.Detection{
		ID: "d1", Type: common.DetectionBeacon, SrcIP: "10.0.0.1",
		Severity: 7, Certainty: 8, Timestamp: time.Now(),
		MITRE: common.MITRETechnique{TacticID: "TA0011", TacticName: "Command and Control"},
	})

	// Host B: beacon + lateral movement.
	scorer.AddDetection(&common.Detection{
		ID: "d2", Type: common.DetectionBeacon, SrcIP: "10.0.0.2",
		Severity: 7, Certainty: 8, Timestamp: time.Now(),
		MITRE: common.MITRETechnique{TacticID: "TA0011", TacticName: "Command and Control"},
	})
	scorer.AddDetection(&common.Detection{
		ID: "d3", Type: common.DetectionLateralMovement, SrcIP: "10.0.0.2",
		Severity: 8, Certainty: 7, Timestamp: time.Now(),
		MITRE: common.MITRETechnique{TacticID: "TA0008", TacticName: "Lateral Movement"},
	})

	scoreA := scorer.GetHostScore("10.0.0.1")
	scoreB := scorer.GetHostScore("10.0.0.2")

	if scoreA == nil || scoreB == nil {
		t.Fatal("GetHostScore returned nil")
	}

	t.Logf("Host A (beacon only): threat=%d certainty=%d quadrant=%s",
		scoreA.ThreatScore, scoreA.CertaintyScore, scoreA.Quadrant)
	t.Logf("Host B (beacon+lateral): threat=%d certainty=%d quadrant=%s",
		scoreB.ThreatScore, scoreB.CertaintyScore, scoreB.Quadrant)

	if scoreB.ThreatScore <= scoreA.ThreatScore {
		t.Errorf("Host B (beacon+lateral) threat=%d should be > Host A (beacon only) threat=%d",
			scoreB.ThreatScore, scoreA.ThreatScore)
	}
}

func TestHostScorerMultipleDetectionTypes(t *testing.T) {
	scorer := NewHostScorer(12*time.Hour, DefaultQuadrantConfig())

	now := time.Now()
	scorer.AddDetection(&common.Detection{
		ID: "d1", Type: common.DetectionBeacon, SrcIP: "10.0.0.5",
		Severity: 6, Certainty: 7, Timestamp: now,
		MITRE: common.MITRETechnique{TacticID: "TA0011"},
	})
	scorer.AddDetection(&common.Detection{
		ID: "d2", Type: common.DetectionDNSTunnel, SrcIP: "10.0.0.5",
		Severity: 5, Certainty: 6, Timestamp: now,
		MITRE: common.MITRETechnique{TacticID: "TA0011"},
	})
	scorer.AddDetection(&common.Detection{
		ID: "d3", Type: common.DetectionExfiltration, SrcIP: "10.0.0.5",
		Severity: 8, Certainty: 7, Timestamp: now,
		MITRE: common.MITRETechnique{TacticID: "TA0010"},
	})

	score := scorer.GetHostScore("10.0.0.5")
	if score == nil {
		t.Fatal("nil score")
	}

	if score.ActiveDetections != 3 {
		t.Errorf("ActiveDetections = %d, want 3", score.ActiveDetections)
	}
	if len(score.DetectionTypes) != 3 {
		t.Errorf("DetectionTypes = %d, want 3", len(score.DetectionTypes))
	}
}

func TestHostScorerUnknownHost(t *testing.T) {
	scorer := NewHostScorer(12*time.Hour, DefaultQuadrantConfig())
	score := scorer.GetHostScore("1.2.3.4")
	if score != nil {
		t.Error("expected nil for unknown host")
	}
}

func TestHostScorerStats(t *testing.T) {
	scorer := NewHostScorer(12*time.Hour, DefaultQuadrantConfig())

	scorer.AddDetection(&common.Detection{
		ID: "d1", SrcIP: "10.0.0.1", Severity: 5, Certainty: 5, Timestamp: time.Now(),
	})
	scorer.AddDetection(&common.Detection{
		ID: "d2", SrcIP: "10.0.0.1", Severity: 6, Certainty: 6, Timestamp: time.Now(),
	})
	scorer.AddDetection(&common.Detection{
		ID: "d3", SrcIP: "10.0.0.2", Severity: 7, Certainty: 7, Timestamp: time.Now(),
	})

	hosts, detections := scorer.Stats()
	if hosts != 2 {
		t.Errorf("hosts = %d, want 2", hosts)
	}
	if detections != 3 {
		t.Errorf("detections = %d, want 3", detections)
	}
}

// ---------------------------------------------------------------------------
// Tactic progression tests (P6-T2)
// ---------------------------------------------------------------------------

func TestTacticProgressionMultiplier(t *testing.T) {
	tests := []struct {
		name    string
		tactics []string
		minMult float64
		maxMult float64
	}{
		{"single tactic", []string{"TA0011"}, 1.0, 1.0},
		{"two tactics same stage", []string{"TA0011", "TA0009"}, 1.0, 1.0}, // both stage 6
		{"two tactics different stages", []string{"TA0011", "TA0008"}, 1.2, 1.4},
		{"full kill chain", []string{"TA0007", "TA0006", "TA0008", "TA0010"}, 1.9, 3.1},
	}

	for _, tt := range tests {
		mult := TacticProgressionMultiplier(tt.tactics)
		if mult < tt.minMult || mult > tt.maxMult {
			t.Errorf("%s: mult=%.1f, want [%.1f, %.1f]", tt.name, mult, tt.minMult, tt.maxMult)
		}
	}
}

func TestFullKillChainScoresCritical(t *testing.T) {
	scorer := NewHostScorer(12*time.Hour, DefaultQuadrantConfig())

	now := time.Now()
	// Simulate full kill chain: Recon → Cred Access → Lateral → Exfil.
	detections := []struct {
		dtype   common.DetectionType
		tactic  string
		sev, cert int
	}{
		{common.DetectionPortScan, "TA0007", 5, 6},         // Discovery
		{common.DetectionKerberoasting, "TA0006", 8, 8},    // Credential Access
		{common.DetectionLateralMovement, "TA0008", 8, 7},  // Lateral Movement
		{common.DetectionExfiltration, "TA0010", 9, 8},     // Exfiltration
	}

	for i, d := range detections {
		scorer.AddDetection(&common.Detection{
			ID: string(rune('a' + i)), Type: d.dtype, SrcIP: "10.0.0.99",
			Severity: common.Severity(d.sev), Certainty: common.Severity(d.cert),
			Timestamp: now,
			MITRE: common.MITRETechnique{TacticID: d.tactic},
		})
	}

	score := scorer.GetHostScore("10.0.0.99")
	if score == nil {
		t.Fatal("nil score")
	}

	t.Logf("Kill chain host: threat=%d certainty=%d quadrant=%s tactics=%v",
		score.ThreatScore, score.CertaintyScore, score.Quadrant, score.MITRETacticsObserved)

	if score.Quadrant != common.QuadrantCritical && score.Quadrant != common.QuadrantHigh {
		t.Errorf("Full kill chain should be Critical or High, got %s", score.Quadrant)
	}
}

// ---------------------------------------------------------------------------
// Score decay tests (P6-T3)
// ---------------------------------------------------------------------------

func TestDecayFactorRecent(t *testing.T) {
	now := time.Now()
	factor := DecayFactor(now, now, 12*time.Hour)
	if factor != 1.0 {
		t.Errorf("decay factor for now = %f, want 1.0", factor)
	}
}

func TestDecayFactorOneHalfLife(t *testing.T) {
	now := time.Now()
	past := now.Add(-12 * time.Hour)
	factor := DecayFactor(past, now, 12*time.Hour)
	if factor < 0.49 || factor > 0.51 {
		t.Errorf("decay factor at 1 half-life = %f, want ~0.5", factor)
	}
}

func TestDecayFactorTwoHalfLives(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	factor := DecayFactor(past, now, 12*time.Hour)
	if factor < 0.24 || factor > 0.26 {
		t.Errorf("decay factor at 2 half-lives = %f, want ~0.25", factor)
	}
}

func TestOlderDetectionContributesLess(t *testing.T) {
	now := time.Now()
	recentScore := DecayedScore(10, now.Add(-1*time.Hour), now, 12*time.Hour)
	oldScore := DecayedScore(10, now.Add(-24*time.Hour), now, 12*time.Hour)

	if oldScore >= recentScore {
		t.Errorf("old score (%.2f) should be < recent score (%.2f)", oldScore, recentScore)
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Now()
	halfLife := 12 * time.Hour

	// 1 day old — not expired (< 7 half-lives = 84h).
	if IsExpired(now.Add(-24*time.Hour), now, halfLife) {
		t.Error("24h old should not be expired with 12h half-life")
	}

	// 5 days old — expired (> 7 * 12h = 84h).
	if !IsExpired(now.Add(-120*time.Hour), now, halfLife) {
		t.Error("120h old should be expired with 12h half-life")
	}
}

func TestHostScorerDecayEffect(t *testing.T) {
	scorer := NewHostScorer(1*time.Hour, DefaultQuadrantConfig()) // 1h half-life for fast test

	now := time.Now()

	// Host A: detection just now.
	scorer.AddDetection(&common.Detection{
		ID: "d1", SrcIP: "10.0.0.1", Severity: 8, Certainty: 8, Timestamp: now,
	})

	// Host B: same detection but 4 hours ago (4 half-lives → ~6% contribution).
	scorer.AddDetection(&common.Detection{
		ID: "d2", SrcIP: "10.0.0.2", Severity: 8, Certainty: 8,
		Timestamp: now.Add(-4 * time.Hour),
	})

	scoreA := scorer.GetHostScore("10.0.0.1")
	scoreB := scorer.GetHostScore("10.0.0.2")

	if scoreA == nil || scoreB == nil {
		t.Fatal("nil score")
	}

	if scoreB.ThreatScore >= scoreA.ThreatScore {
		t.Errorf("Old detection host B (threat=%d) should score lower than recent host A (threat=%d)",
			scoreB.ThreatScore, scoreA.ThreatScore)
	}
}

// ---------------------------------------------------------------------------
// Quadrant classification tests (P6-T4)
// ---------------------------------------------------------------------------

func TestQuadrantClassification(t *testing.T) {
	cfg := DefaultQuadrantConfig()

	tests := []struct {
		threat, certainty int
		want              common.Quadrant
	}{
		{10, 10, common.QuadrantLow},
		{30, 10, common.QuadrantMedium},
		{10, 30, common.QuadrantMedium},
		{60, 30, common.QuadrantHigh},
		{30, 60, common.QuadrantHigh},
		{80, 80, common.QuadrantCritical},
		{90, 90, common.QuadrantCritical},
		{71, 71, common.QuadrantCritical},
		{71, 50, common.QuadrantHigh},  // Only one above critical
		{0, 0, common.QuadrantLow},
		{100, 100, common.QuadrantCritical},
	}

	for _, tt := range tests {
		got := ClassifyQuadrant(tt.threat, tt.certainty, cfg)
		if got != tt.want {
			t.Errorf("ClassifyQuadrant(%d, %d) = %s, want %s",
				tt.threat, tt.certainty, got, tt.want)
		}
	}
}

func TestQuadrantConfigurable(t *testing.T) {
	// Stricter config: critical requires both > 90.
	cfg := QuadrantConfig{CriticalThreshold: 90, HighThreshold: 60, MediumThreshold: 30}

	// 80,80 would be Critical with defaults but only High with stricter config.
	got := ClassifyQuadrant(80, 80, cfg)
	if got != common.QuadrantHigh {
		t.Errorf("got %s, want High with strict config", got)
	}

	// 95,95 → Critical even with strict config.
	got = ClassifyQuadrant(95, 95, cfg)
	if got != common.QuadrantCritical {
		t.Errorf("got %s, want Critical", got)
	}
}

func TestCleanupRemovesExpired(t *testing.T) {
	scorer := NewHostScorer(1*time.Hour, DefaultQuadrantConfig())

	// Add an old detection (well past expiration).
	scorer.AddDetection(&common.Detection{
		ID: "old", SrcIP: "10.0.0.1", Severity: 5, Certainty: 5,
		Timestamp: time.Now().Add(-200 * time.Hour), // Way past 7 half-lives
	})

	hosts, _ := scorer.Stats()
	if hosts != 1 {
		t.Fatalf("expected 1 host before cleanup, got %d", hosts)
	}

	scorer.Cleanup()

	hosts, _ = scorer.Stats()
	if hosts != 0 {
		t.Errorf("expected 0 hosts after cleanup, got %d", hosts)
	}
}
