package detect

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// LateralMovementDetector identifies internal host-to-host movement using
// SMB, RPC, WMI, RDP, and SSH. Tracks per-host connection fan-out,
// admin share access, and DCE-RPC service creation patterns.
type LateralMovementDetector struct {
	mu  sync.Mutex
	cfg config.LateralMoveConfig
	// Key: source IP, Value: set of destination IPs + connection metadata.
	hosts map[string]*lateralHost
}

type lateralHost struct {
	destinations map[string]*lateralDest // key: dstIP
	adminShares  int                     // ADMIN$, C$, IPC$ access count
	svcctlOps    int                     // svcctl/CreateServiceW count
	wmiOps       int                     // WMI operations count
	rdpConns     int                     // RDP connections
	firstSeen    time.Time
	lastSeen     time.Time
}

type lateralDest struct {
	protocols []string // which protocols seen: smb, dcerpc, rdp, ssh
	firstSeen time.Time
}

// NewLateralMovementDetector creates a lateral movement detector.
func NewLateralMovementDetector(cfg config.LateralMoveConfig) *LateralMovementDetector {
	return &LateralMovementDetector{
		cfg:   cfg,
		hosts: make(map[string]*lateralHost),
	}
}

func (d *LateralMovementDetector) Name() string               { return "Lateral Movement Detector" }
func (d *LateralMovementDetector) Type() common.DetectionType  { return common.DetectionLateralMovement }

func (d *LateralMovementDetector) ProcessSession(session *common.SessionMeta) {
	// Track SMB (445), RDP (3389), SSH (22) sessions between internal hosts.
	dstPort := session.Flow.DstPort
	if dstPort != 445 && dstPort != 3389 && dstPort != 22 && dstPort != 135 {
		return
	}

	srcIP := session.Flow.SrcIP.String()
	dstIP := session.Flow.DstIP.String()

	protocol := "unknown"
	switch dstPort {
	case 445:
		protocol = "smb"
	case 3389:
		protocol = "rdp"
	case 22:
		protocol = "ssh"
	case 135:
		protocol = "dcerpc"
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	host, ok := d.hosts[srcIP]
	if !ok {
		host = &lateralHost{
			destinations: make(map[string]*lateralDest),
			firstSeen:    time.Now(),
		}
		d.hosts[srcIP] = host
	}
	host.lastSeen = time.Now()

	if dstPort == 3389 {
		host.rdpConns++
	}

	dest, ok := host.destinations[dstIP]
	if !ok {
		dest = &lateralDest{firstSeen: time.Now()}
		host.destinations[dstIP] = dest
	}
	dest.protocols = appendUnique(dest.protocols, protocol)
}

func (d *LateralMovementDetector) ProcessProtocol(meta any, protocol string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch protocol {
	case "smb":
		if sm, ok := meta.(*common.SMBMeta); ok {
			// Detect admin share access.
			if sm.Path != "" {
				upper := strings.ToUpper(sm.Path)
				if strings.Contains(upper, "ADMIN$") || strings.Contains(upper, "C$") {
					// We don't have srcIP here directly; track globally.
					for _, host := range d.hosts {
						if time.Since(host.lastSeen) < 5*time.Second {
							host.adminShares++
						}
					}
				}
			}
		}
	case "dcerpc":
		if dm, ok := meta.(*common.DCERPCMeta); ok {
			for _, host := range d.hosts {
				if time.Since(host.lastSeen) < 5*time.Second {
					if dm.Endpoint == "svcctl" {
						host.svcctlOps++
					}
					if dm.Endpoint == "IWbemLoginClientID" {
						host.wmiOps++
					}
				}
			}
		}
	}
}

func (d *LateralMovementDetector) Check() []*common.Detection {
	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []*common.Detection
	fanOutThreshold := d.cfg.FanOutThreshold
	if fanOutThreshold <= 0 {
		fanOutThreshold = 5
	}

	for srcIP, host := range d.hosts {
		fanOut := len(host.destinations)
		score := 0.0

		// Fan-out: connecting to many internal hosts.
		if fanOut >= fanOutThreshold {
			score += float64(fanOut)
		}

		// Admin share access (PsExec pattern).
		if host.adminShares > 0 {
			score += 3.0
		}

		// Service creation via svcctl (PsExec pattern).
		if host.svcctlOps > 0 {
			score += 4.0
		}

		// WMI remote execution.
		if host.wmiOps > 0 {
			score += 3.0
		}

		// Workstation-to-workstation RDP (unusual).
		if host.rdpConns > 2 {
			score += 2.0
		}

		if score < 4.0 {
			continue
		}

		severity := common.Severity(clampInt(int(score), 1, 10))
		certainty := common.Severity(clampInt(int(score*0.8), 1, 10))

		destList := make([]string, 0, len(host.destinations))
		for dst := range host.destinations {
			destList = append(destList, dst)
		}

		alert := &common.Detection{
			ID:        fmt.Sprintf("lateral-%s-%d", srcIP, time.Now().UnixNano()),
			Name:      "Lateral Movement Detected",
			Type:      common.DetectionLateralMovement,
			Timestamp: time.Now(),
			Severity:  severity,
			Certainty: certainty,
			MITRE:     mitreLateralMovement(),
			SrcIP:     srcIP,
			Evidence: map[string]any{
				"fan_out":       fanOut,
				"destinations":  destList,
				"admin_shares":  host.adminShares,
				"svcctl_ops":    host.svcctlOps,
				"wmi_ops":       host.wmiOps,
				"rdp_conns":     host.rdpConns,
				"score":         score,
			},
			Description: fmt.Sprintf("Lateral movement from %s: fan_out=%d, admin$=%d, svcctl=%d, wmi=%d",
				srcIP, fanOut, host.adminShares, host.svcctlOps, host.wmiOps),
		}
		alerts = append(alerts, alert)

		// Reset host to avoid re-alerting.
		delete(d.hosts, srcIP)
	}

	return alerts
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
