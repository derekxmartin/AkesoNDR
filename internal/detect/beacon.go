package detect

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// BeaconDetector identifies C2 beaconing by analyzing outbound session
// timing patterns. It maintains per-destination session histories and
// computes: mean interval, standard deviation, coefficient of variation,
// and payload size consistency. Regular intervals with low jitter and
// consistent sizes produce high beacon scores.
type BeaconDetector struct {
	mu   sync.Mutex
	cfg  config.BeaconConfig
	// Key: "srcIP→dstIP:dstPort", Value: session timestamps + sizes.
	flows map[string]*beaconFlow
}

type beaconFlow struct {
	srcIP      string
	dstIP      string
	dstPort    uint16
	timestamps []time.Time
	sizes      []uint64
}

// NewBeaconDetector creates a beacon detector with the given config.
func NewBeaconDetector(cfg config.BeaconConfig) *BeaconDetector {
	return &BeaconDetector{
		cfg:   cfg,
		flows: make(map[string]*beaconFlow),
	}
}

func (d *BeaconDetector) Name() string                 { return "C2 Beacon Detector" }
func (d *BeaconDetector) Type() common.DetectionType   { return common.DetectionBeacon }

func (d *BeaconDetector) ProcessSession(session *common.SessionMeta) {
	// Only track outbound TCP/UDP sessions.
	if session.Transport != common.TransportTCP && session.Transport != common.TransportUDP {
		return
	}

	srcIP := session.Flow.SrcIP.String()
	dstIP := session.Flow.DstIP.String()
	dstPort := session.Flow.DstPort

	key := fmt.Sprintf("%s→%s:%d", srcIP, dstIP, dstPort)

	d.mu.Lock()
	defer d.mu.Unlock()

	flow, ok := d.flows[key]
	if !ok {
		flow = &beaconFlow{srcIP: srcIP, dstIP: dstIP, dstPort: dstPort}
		d.flows[key] = flow
	}

	flow.timestamps = append(flow.timestamps, session.StartTime)
	flow.sizes = append(flow.sizes, session.OrigBytes+session.RespBytes)
}

func (d *BeaconDetector) ProcessProtocol(meta any, protocol string) {}

func (d *BeaconDetector) Check() []*common.Detection {
	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []*common.Detection
	minSessions := d.cfg.MinSessions
	if minSessions <= 0 {
		minSessions = 10
	}
	maxJitter := d.cfg.MaxJitterRatio
	if maxJitter <= 0 {
		maxJitter = 0.2
	}

	for key, flow := range d.flows {
		if len(flow.timestamps) < minSessions {
			continue
		}

		// Compute inter-session intervals.
		intervals := computeIntervals(flow.timestamps)
		if len(intervals) < 2 {
			continue
		}

		mean, stddev := meanStdDev(intervals)
		if mean <= 0 {
			continue
		}

		cv := stddev / mean // coefficient of variation

		// Beacon score: low CV = high confidence.
		if cv > maxJitter {
			continue // Too much jitter — not a beacon.
		}

		// Compute size consistency.
		sizeMean, sizeStddev := meanStdDevUint64(flow.sizes)
		sizeCV := 1.0
		if sizeMean > 0 {
			sizeCV = sizeStddev / sizeMean
		}

		// Severity scales with session count and regularity.
		severity := common.Severity(clampInt(5+len(flow.timestamps)/10, 1, 10))
		certainty := common.Severity(10 - int(cv*30))
		if certainty < 1 {
			certainty = 1
		}
		if sizeCV < 0.1 {
			if certainty+2 <= 10 {
				certainty += 2
			} else {
				certainty = 10
			}
		}

		alert := &common.Detection{
			ID:        fmt.Sprintf("beacon-%s-%d", key, time.Now().UnixNano()),
			Name:      "C2 Beacon Detected",
			Type:      common.DetectionBeacon,
			Timestamp: time.Now(),
			Severity:  severity,
			Certainty: certainty,
			MITRE:     mitreBeacon(),
			SrcIP:     flow.srcIP,
			DstIP:     flow.dstIP,
			DstPort:   flow.dstPort,
			Evidence: map[string]any{
				"session_count":   len(flow.timestamps),
				"interval_mean":   mean,
				"interval_stddev": stddev,
				"cv":              cv,
				"size_mean":       sizeMean,
				"size_cv":         sizeCV,
			},
			Description: fmt.Sprintf("Regular beaconing: %d sessions, interval=%.1fs (CV=%.3f), size_cv=%.3f",
				len(flow.timestamps), mean, cv, sizeCV),
		}
		alerts = append(alerts, alert)

		// Reset flow to avoid re-alerting (keep last few for continuity).
		n := len(flow.timestamps)
		if n > 3 {
			flow.timestamps = flow.timestamps[n-3:]
			flow.sizes = flow.sizes[n-3:]
		}
	}

	return alerts
}

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

func computeIntervals(timestamps []time.Time) []float64 {
	if len(timestamps) < 2 {
		return nil
	}
	intervals := make([]float64, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		dt := timestamps[i].Sub(timestamps[i-1]).Seconds()
		if dt > 0 {
			intervals = append(intervals, dt)
		}
	}
	return intervals
}

func meanStdDev(vals []float64) (mean, stddev float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	mean = sum / float64(len(vals))

	sumSq := 0.0
	for _, v := range vals {
		diff := v - mean
		sumSq += diff * diff
	}
	stddev = math.Sqrt(sumSq / float64(len(vals)))
	return
}

func meanStdDevUint64(vals []uint64) (mean, stddev float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	fvals := make([]float64, len(vals))
	for i, v := range vals {
		fvals[i] = float64(v)
	}
	return meanStdDev(fvals)
}

