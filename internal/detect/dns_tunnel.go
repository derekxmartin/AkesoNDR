package detect

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
	ndrdns "github.com/akesondr/akeso-ndr/internal/protocols/dns"
)

// DNSTunnelDetector identifies DNS-based data exfiltration and C2 by
// analyzing query characteristics: Shannon entropy, subdomain depth,
// query volume per parent domain, and TXT record ratio.
type DNSTunnelDetector struct {
	mu      sync.Mutex
	cfg     config.DNSTunnelConfig
	domains map[string]*domainStats // Key: parent domain
}

type domainStats struct {
	queryCount   int
	txtCount     int
	nxCount      int
	totalEntropy float64
	maxDepth     int
	maxLength    int
	srcIPs       map[string]bool
	firstSeen    time.Time
	lastSeen     time.Time
}

// NewDNSTunnelDetector creates a DNS tunnel detector with the given config.
func NewDNSTunnelDetector(cfg config.DNSTunnelConfig) *DNSTunnelDetector {
	return &DNSTunnelDetector{
		cfg:     cfg,
		domains: make(map[string]*domainStats),
	}
}

func (d *DNSTunnelDetector) Name() string               { return "DNS Tunnel Detector" }
func (d *DNSTunnelDetector) Type() common.DetectionType  { return common.DetectionDNSTunnel }

func (d *DNSTunnelDetector) ProcessSession(session *common.SessionMeta) {}

func (d *DNSTunnelDetector) ProcessProtocol(meta any, protocol string) {
	if protocol != "dns" {
		return
	}
	dm, ok := meta.(*common.DNSMeta)
	if !ok || dm == nil {
		return
	}

	parent := parentDomain(dm.Query)
	if parent == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	stats, ok := d.domains[parent]
	if !ok {
		stats = &domainStats{
			srcIPs:    make(map[string]bool),
			firstSeen: time.Now(),
		}
		d.domains[parent] = stats
	}

	stats.queryCount++
	stats.lastSeen = time.Now()
	stats.totalEntropy += dm.Entropy

	if dm.QTypeName == "TXT" {
		stats.txtCount++
	}
	if dm.RCodeName == "NXDOMAIN" {
		stats.nxCount++
	}
	if dm.SubdomainDepth > stats.maxDepth {
		stats.maxDepth = dm.SubdomainDepth
	}
	if dm.QueryLength > stats.maxLength {
		stats.maxLength = dm.QueryLength
	}
}

func (d *DNSTunnelDetector) Check() []*common.Detection {
	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []*common.Detection
	entropyThreshold := d.cfg.EntropyThreshold
	if entropyThreshold <= 0 {
		entropyThreshold = 3.5
	}
	volumeThreshold := d.cfg.QueryVolumeThreshold
	if volumeThreshold <= 0 {
		volumeThreshold = 100
	}
	maxDepth := d.cfg.MaxSubdomainDepth
	if maxDepth <= 0 {
		maxDepth = 5
	}

	for domain, stats := range d.domains {
		if stats.queryCount < 10 {
			continue // Need minimum sample.
		}

		avgEntropy := stats.totalEntropy / float64(stats.queryCount)
		score := 0.0

		// High entropy queries → likely encoded data.
		if avgEntropy > entropyThreshold {
			score += 3.0
		}

		// High query volume to single domain.
		if stats.queryCount > volumeThreshold {
			score += 2.0
		}

		// Deep subdomains.
		if stats.maxDepth > maxDepth {
			score += 2.0
		}

		// High TXT ratio (TXT carries more data).
		txtRatio := float64(stats.txtCount) / float64(stats.queryCount)
		if txtRatio > 0.3 {
			score += 1.5
		}

		// Long query names.
		if stats.maxLength > 50 {
			score += 1.5
		}

		if score < 4.0 {
			continue // Below detection threshold.
		}

		severity := common.Severity(clampInt(int(score), 1, 10))
		certainty := common.Severity(clampInt(int(score*1.2), 1, 10))

		alert := &common.Detection{
			ID:        fmt.Sprintf("dns-tunnel-%s-%d", domain, time.Now().UnixNano()),
			Name:      "DNS Tunneling Detected",
			Type:      common.DetectionDNSTunnel,
			Timestamp: time.Now(),
			Severity:  severity,
			Certainty: certainty,
			MITRE:     mitreDNSTunnel(),
			Evidence: map[string]any{
				"parent_domain": domain,
				"query_count":   stats.queryCount,
				"avg_entropy":   avgEntropy,
				"max_depth":     stats.maxDepth,
				"max_length":    stats.maxLength,
				"txt_ratio":     txtRatio,
				"score":         score,
			},
			Description: fmt.Sprintf("DNS tunnel via %s: %d queries, entropy=%.2f, depth=%d, txt_ratio=%.1f%%",
				domain, stats.queryCount, avgEntropy, stats.maxDepth, txtRatio*100),
		}
		alerts = append(alerts, alert)

		// Reset to avoid re-alerting.
		delete(d.domains, domain)
	}

	return alerts
}

// parentDomain extracts the registrable domain from an FQDN.
// "a.b.c.evil.com" → "evil.com"
func parentDomain(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return fqdn
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// ShannonEntropy wraps the DNS package's entropy computation for reuse.
var ShannonEntropy = ndrdns.ShannonEntropy

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
