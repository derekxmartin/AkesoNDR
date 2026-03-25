package detect

import (
	"fmt"
	"sync"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// PortScanDetector identifies port scanning and service enumeration by
// analyzing connection state patterns. Horizontal scans (one source, many
// destinations, same port), vertical scans (one source, one destination,
// many ports), and connection state analysis (S0/REJ at scale = scanning).
type PortScanDetector struct {
	mu  sync.Mutex
	cfg config.ScanConfig
	// Per-source IP tracking.
	sources map[string]*scanSource
}

type scanSource struct {
	// Horizontal: unique destination IPs per destination port.
	horizTargets map[uint16]map[string]bool // dstPort → set of dstIPs

	// Vertical: unique destination ports per destination IP.
	vertPorts map[string]map[uint16]bool // dstIP → set of dstPorts

	// Connection state counts — S0 and REJ indicate scan behavior.
	s0Count  int
	rejCount int

	totalConns int
	firstSeen  time.Time
	lastSeen   time.Time
}

// NewPortScanDetector creates a port scan detector.
func NewPortScanDetector(cfg config.ScanConfig) *PortScanDetector {
	return &PortScanDetector{
		cfg:     cfg,
		sources: make(map[string]*scanSource),
	}
}

func (d *PortScanDetector) Name() string               { return "Port Scan Detector" }
func (d *PortScanDetector) Type() common.DetectionType  { return common.DetectionPortScan }

func (d *PortScanDetector) ProcessSession(session *common.SessionMeta) {
	srcIP := session.Flow.SrcIP.String()
	dstIP := session.Flow.DstIP.String()
	dstPort := session.Flow.DstPort

	d.mu.Lock()
	defer d.mu.Unlock()

	src, ok := d.sources[srcIP]
	if !ok {
		src = &scanSource{
			horizTargets: make(map[uint16]map[string]bool),
			vertPorts:    make(map[string]map[uint16]bool),
			firstSeen:    time.Now(),
		}
		d.sources[srcIP] = src
	}
	src.lastSeen = time.Now()
	src.totalConns++

	// Track horizontal scan pattern.
	if src.horizTargets[dstPort] == nil {
		src.horizTargets[dstPort] = make(map[string]bool)
	}
	src.horizTargets[dstPort][dstIP] = true

	// Track vertical scan pattern.
	if src.vertPorts[dstIP] == nil {
		src.vertPorts[dstIP] = make(map[uint16]bool)
	}
	src.vertPorts[dstIP][dstPort] = true

	// Track connection states (S0 = SYN no reply, REJ = rejected).
	switch session.ConnState {
	case common.ConnStateS0:
		src.s0Count++
	case common.ConnStateREJ:
		src.rejCount++
	}
}

func (d *PortScanDetector) ProcessProtocol(meta any, protocol string) {}

func (d *PortScanDetector) Check() []*common.Detection {
	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []*common.Detection
	hostThreshold := d.cfg.HostThreshold
	if hostThreshold <= 0 {
		hostThreshold = 25
	}
	portThreshold := d.cfg.PortThreshold
	if portThreshold <= 0 {
		portThreshold = 50
	}

	for srcIP, src := range d.sources {
		scanType := ""
		score := 0.0
		details := map[string]any{}

		// --- Horizontal scan: same port, many destinations ---
		for port, targets := range src.horizTargets {
			if len(targets) >= hostThreshold {
				scanType = "horizontal"
				score += float64(len(targets)) / float64(hostThreshold) * 5
				details["horiz_port"] = port
				details["horiz_targets"] = len(targets)
				break
			}
		}

		// --- Vertical scan: same destination, many ports ---
		for dstIP, ports := range src.vertPorts {
			if len(ports) >= portThreshold {
				if scanType == "" {
					scanType = "vertical"
				} else {
					scanType = "combined"
				}
				score += float64(len(ports)) / float64(portThreshold) * 5
				details["vert_dst"] = dstIP
				details["vert_ports"] = len(ports)
				break
			}
		}

		// S0/REJ ratio amplifies scan confidence.
		failConns := src.s0Count + src.rejCount
		if src.totalConns > 10 {
			failRatio := float64(failConns) / float64(src.totalConns)
			if failRatio > 0.5 {
				score += 3.0
				details["fail_ratio"] = failRatio
			}
		}

		if score < 4.0 || scanType == "" {
			continue
		}

		severity := common.Severity(clampInt(int(score), 3, 10))
		certainty := common.Severity(clampInt(int(score*0.9), 3, 10))

		details["scan_type"] = scanType
		details["total_conns"] = src.totalConns
		details["s0_count"] = src.s0Count
		details["rej_count"] = src.rejCount
		details["score"] = score

		alert := &common.Detection{
			ID:        fmt.Sprintf("scan-%s-%d", srcIP, time.Now().UnixNano()),
			Name:      "Port Scan Detected",
			Type:      common.DetectionPortScan,
			Timestamp: time.Now(),
			Severity:  severity,
			Certainty: certainty,
			MITRE:     mitrePortScan(),
			SrcIP:     srcIP,
			Evidence:  details,
			Description: fmt.Sprintf("Port scan from %s: type=%s, conns=%d, s0=%d, rej=%d",
				srcIP, scanType, src.totalConns, src.s0Count, src.rejCount),
		}
		alerts = append(alerts, alert)

		// Reset to avoid re-alerting.
		delete(d.sources, srcIP)
	}

	return alerts
}
