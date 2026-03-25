package detect

import (
	"fmt"
	"sync"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// MITRE mappings for Kerberos attacks.
func mitreKerberoasting() common.MITRETechnique {
	return common.MITRETechnique{
		TechniqueID: "T1558.003", TechniqueName: "Kerberoasting",
		TacticID: "TA0006", TacticName: "Credential Access",
	}
}

func mitreASREPRoast() common.MITRETechnique {
	return common.MITRETechnique{
		TechniqueID: "T1558.004", TechniqueName: "AS-REP Roasting",
		TacticID: "TA0006", TacticName: "Credential Access",
	}
}

func mitreBruteForce() common.MITRETechnique {
	return common.MITRETechnique{
		TechniqueID: "T1110", TechniqueName: "Brute Force",
		TacticID: "TA0006", TacticName: "Credential Access",
	}
}

// KerberosAttackDetector identifies Kerberos-based credential attacks:
// Kerberoasting (high-volume TGS-REQ with RC4), AS-REP roasting
// (AS-REP with RC4 for pre-auth disabled accounts), and brute force
// (high rate of PREAUTH_FAILED errors).
type KerberosAttackDetector struct {
	mu  sync.Mutex
	cfg config.KerberosConfig
	// Per-source IP tracking.
	sources map[string]*krbSource
}

type krbSource struct {
	tgsRequests    int
	tgsRC4Count    int // TGS requests with etype 23 (RC4)
	asRepRC4Count  int // AS-REP with RC4 reply cipher
	preauthFails   int // KDC_ERR_PREAUTH_FAILED count
	firstSeen      time.Time
	lastSeen       time.Time
}

// NewKerberosAttackDetector creates a Kerberos attack detector.
func NewKerberosAttackDetector(cfg config.KerberosConfig) *KerberosAttackDetector {
	return &KerberosAttackDetector{
		cfg:     cfg,
		sources: make(map[string]*krbSource),
	}
}

func (d *KerberosAttackDetector) Name() string               { return "Kerberos Attack Detector" }
func (d *KerberosAttackDetector) Type() common.DetectionType  { return common.DetectionKerberoasting }

func (d *KerberosAttackDetector) ProcessSession(session *common.SessionMeta) {}

func (d *KerberosAttackDetector) ProcessProtocol(meta any, protocol string) {
	if protocol != "kerberos" {
		return
	}
	km, ok := meta.(*common.KerberosMeta)
	if !ok || km == nil {
		return
	}

	// We need a source IP — use client principal as proxy since we don't
	// have the network flow here. In practice the engine would pass both.
	srcKey := km.Client
	if srcKey == "" {
		srcKey = "unknown"
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	src, ok := d.sources[srcKey]
	if !ok {
		src = &krbSource{firstSeen: time.Now()}
		d.sources[srcKey] = src
	}
	src.lastSeen = time.Now()

	switch km.RequestType {
	case "TGS":
		src.tgsRequests++
		// Check for RC4 (etype 23) in requested ciphers.
		for _, etype := range km.ReqCiphers {
			if etype == 23 {
				src.tgsRC4Count++
				break
			}
		}

	case "AS":
		// AS-REP with RC4 reply cipher → AS-REP roasting indicator.
		if km.Success && km.RepCipher == 23 {
			src.asRepRC4Count++
		}
		// Preauth failure.
		if km.ErrorCode == 24 { // KDC_ERR_PREAUTH_FAILED
			src.preauthFails++
		}
	}
}

func (d *KerberosAttackDetector) Check() []*common.Detection {
	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []*common.Detection
	tgsThreshold := d.cfg.TGSRequestThreshold
	if tgsThreshold <= 0 {
		tgsThreshold = 10
	}

	for srcKey, src := range d.sources {
		// --- Kerberoasting: high-volume TGS-REQ with RC4 ---
		if src.tgsRC4Count >= tgsThreshold {
			severity := common.Severity(clampInt(5+src.tgsRC4Count/5, 5, 10))
			alerts = append(alerts, &common.Detection{
				ID:        fmt.Sprintf("kerberoast-%s-%d", srcKey, time.Now().UnixNano()),
				Name:      "Kerberoasting Detected",
				Type:      common.DetectionKerberoasting,
				Timestamp: time.Now(),
				Severity:  severity,
				Certainty: 8,
				MITRE:     mitreKerberoasting(),
				SrcIP:     srcKey,
				Evidence: map[string]any{
					"tgs_total":     src.tgsRequests,
					"tgs_rc4_count": src.tgsRC4Count,
					"window":        src.lastSeen.Sub(src.firstSeen).String(),
				},
				Description: fmt.Sprintf("Kerberoasting from %s: %d TGS-REQ with RC4 (etype 23) in %s",
					srcKey, src.tgsRC4Count, src.lastSeen.Sub(src.firstSeen).Round(time.Second)),
			})
			delete(d.sources, srcKey)
			continue
		}

		// --- AS-REP Roasting: AS-REP with RC4 ---
		if src.asRepRC4Count >= 3 {
			alerts = append(alerts, &common.Detection{
				ID:        fmt.Sprintf("asrep-roast-%s-%d", srcKey, time.Now().UnixNano()),
				Name:      "AS-REP Roasting Detected",
				Type:      common.DetectionASREPRoast,
				Timestamp: time.Now(),
				Severity:  7,
				Certainty: 7,
				MITRE:     mitreASREPRoast(),
				SrcIP:     srcKey,
				Evidence: map[string]any{
					"asrep_rc4_count": src.asRepRC4Count,
				},
				Description: fmt.Sprintf("AS-REP roasting from %s: %d AS-REP with RC4 cipher",
					srcKey, src.asRepRC4Count),
			})
			delete(d.sources, srcKey)
			continue
		}

		// --- Brute Force: high preauth failure rate ---
		if src.preauthFails >= 10 {
			alerts = append(alerts, &common.Detection{
				ID:        fmt.Sprintf("krb-brute-%s-%d", srcKey, time.Now().UnixNano()),
				Name:      "Kerberos Brute Force Detected",
				Type:      common.DetectionKerberoasting, // reuse type
				Timestamp: time.Now(),
				Severity:  6,
				Certainty: 8,
				MITRE:     mitreBruteForce(),
				SrcIP:     srcKey,
				Evidence: map[string]any{
					"preauth_fails": src.preauthFails,
					"window":        src.lastSeen.Sub(src.firstSeen).String(),
				},
				Description: fmt.Sprintf("Kerberos brute force from %s: %d PREAUTH_FAILED in %s",
					srcKey, src.preauthFails, src.lastSeen.Sub(src.firstSeen).Round(time.Second)),
			})
			delete(d.sources, srcKey)
			continue
		}
	}

	return alerts
}
