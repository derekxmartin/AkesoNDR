package detect

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// ExfilDetector identifies data exfiltration by monitoring outbound
// transfer volumes per host. It computes a rolling baseline and alerts
// when outbound volume exceeds the baseline by a configurable number
// of standard deviations, or when absolute volume thresholds are exceeded.
type ExfilDetector struct {
	mu    sync.Mutex
	cfg   config.ExfilConfig
	hosts map[string]*exfilHost // Key: source IP
}

type exfilHost struct {
	// Rolling windows of outbound bytes (one entry per check interval).
	outboundHistory []float64
	// Current accumulator for outbound bytes since last check.
	currentOutbound uint64
	currentInbound  uint64
	sessionCount    int
	lastSeen        time.Time
}

// NewExfilDetector creates an exfiltration detector with the given config.
func NewExfilDetector(cfg config.ExfilConfig) *ExfilDetector {
	return &ExfilDetector{
		cfg:   cfg,
		hosts: make(map[string]*exfilHost),
	}
}

func (d *ExfilDetector) Name() string               { return "Exfiltration Detector" }
func (d *ExfilDetector) Type() common.DetectionType  { return common.DetectionExfiltration }

func (d *ExfilDetector) ProcessSession(session *common.SessionMeta) {
	srcIP := session.Flow.SrcIP.String()

	d.mu.Lock()
	defer d.mu.Unlock()

	host, ok := d.hosts[srcIP]
	if !ok {
		host = &exfilHost{}
		d.hosts[srcIP] = host
	}

	host.currentOutbound += session.OrigBytes
	host.currentInbound += session.RespBytes
	host.sessionCount++
	host.lastSeen = time.Now()
}

func (d *ExfilDetector) ProcessProtocol(meta any, protocol string) {}

func (d *ExfilDetector) Check() []*common.Detection {
	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []*common.Detection
	deviationThreshold := d.cfg.DeviationThreshold
	if deviationThreshold <= 0 {
		deviationThreshold = 3.0
	}
	absoluteThresholdBytes := uint64(d.cfg.AbsoluteThresholdMB) * 1024 * 1024
	if absoluteThresholdBytes == 0 {
		absoluteThresholdBytes = 500 * 1024 * 1024 // 500 MB default
	}
	maxHistory := 60 // ~60 check intervals of history

	for srcIP, host := range d.hosts {
		outbound := float64(host.currentOutbound)

		// Add current window to history.
		host.outboundHistory = append(host.outboundHistory, outbound)
		if len(host.outboundHistory) > maxHistory {
			host.outboundHistory = host.outboundHistory[1:]
		}

		// Reset current accumulators.
		host.currentOutbound = 0
		host.currentInbound = 0
		host.sessionCount = 0

		// Need enough history for baseline.
		if len(host.outboundHistory) < 5 {
			continue
		}

		// Compute baseline from history (excluding current window).
		history := host.outboundHistory[:len(host.outboundHistory)-1]
		mean, stddev := meanStdDev(history)

		// Z-score of current outbound volume.
		zscore := 0.0
		if stddev > 0 {
			zscore = (outbound - mean) / stddev
		}

		shouldAlert := false
		reason := ""

		// Deviation-based: outbound exceeds baseline by N standard deviations.
		if zscore > deviationThreshold && outbound > 1024*1024 { // >1MB minimum
			shouldAlert = true
			reason = fmt.Sprintf("z-score=%.1f (threshold=%.1f)", zscore, deviationThreshold)
		}

		// Absolute threshold: large outbound volume regardless of baseline.
		if uint64(outbound) > absoluteThresholdBytes {
			shouldAlert = true
			reason = fmt.Sprintf("volume=%.1fMB (threshold=%dMB)",
				outbound/(1024*1024), d.cfg.AbsoluteThresholdMB)
		}

		if !shouldAlert {
			continue
		}

		severity := common.Severity(clampInt(int(math.Min(zscore, 10)), 3, 10))
		certainty := common.Severity(clampInt(int(zscore*1.5), 2, 10))

		alert := &common.Detection{
			ID:        fmt.Sprintf("exfil-%s-%d", srcIP, time.Now().UnixNano()),
			Name:      "Data Exfiltration Detected",
			Type:      common.DetectionExfiltration,
			Timestamp: time.Now(),
			Severity:  severity,
			Certainty: certainty,
			MITRE:     mitreExfiltration(),
			SrcIP:     srcIP,
			Evidence: map[string]any{
				"outbound_bytes":  uint64(outbound),
				"baseline_mean":   mean,
				"baseline_stddev": stddev,
				"z_score":         zscore,
				"reason":          reason,
			},
			Description: fmt.Sprintf("Exfiltration from %s: %.1fMB outbound, %s",
				srcIP, outbound/(1024*1024), reason),
		}
		alerts = append(alerts, alert)
	}

	return alerts
}
