package signatures

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// AlertCallback is called when a signature rule matches.
type AlertCallback func(detection *common.Detection)

// Pipeline integrates Suricata signature matching into the AkesoNDR
// detection pipeline. It evaluates loaded rules against session data
// and produces Detection events compatible with the host scoring engine
// and SIEM export.
type Pipeline struct {
	loader  *Loader
	matcher *Matcher
	onAlert AlertCallback
}

// NewPipeline creates a signature detection pipeline.
func NewPipeline(loader *Loader, onAlert AlertCallback) *Pipeline {
	return &Pipeline{
		loader:  loader,
		matcher: NewMatcher(),
		onAlert: onAlert,
	}
}

// EvaluateSession runs all loaded rules against session data and emits
// Detection events for any matches.
func (p *Pipeline) EvaluateSession(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	protocol string,
	clientData, serverData []byte,
) {
	rules := p.loader.Rules()
	if len(rules) == 0 {
		return
	}

	// Filter rules by protocol.
	var applicable []*Rule
	for _, r := range rules {
		if r.Protocol == "any" || r.Protocol == "ip" || r.Protocol == protocol {
			applicable = append(applicable, r)
		}
	}

	results := p.matcher.MatchRules(applicable, clientData, serverData)
	for _, result := range results {
		if !result.Matched {
			continue
		}

		p.loader.IncrementMatches()

		detection := ruleToDetection(result.Rule, srcIP, dstIP, srcPort, dstPort, result.MatchData)

		if p.onAlert != nil {
			p.onAlert(detection)
		}

		log.Printf("[signatures] SID:%d %s | %s:%d → %s:%d",
			result.Rule.SID, result.Rule.Msg,
			srcIP, srcPort, dstIP, dstPort)
	}
}

// ruleToDetection converts a matched Suricata rule into an AkesoNDR Detection.
func ruleToDetection(rule *Rule, srcIP, dstIP net.IP, srcPort, dstPort uint16, matchData []byte) *common.Detection {
	// Map Suricata severity (1=high, 4=low) to AkesoNDR severity (1-10).
	severity := common.Severity(10 - rule.Severity*2)
	if severity < 1 {
		severity = 1
	}
	if severity > 10 {
		severity = 10
	}

	// Map classtype to MITRE technique (best-effort).
	mitre := classtypeToMITRE(rule.Classtype)

	evidence := map[string]any{
		"sid":       fmt.Sprintf("%d", rule.SID),
		"msg":       rule.Msg,
		"classtype": rule.Classtype,
	}
	if len(rule.Reference) > 0 {
		evidence["reference"] = rule.Reference[0]
	}
	if len(matchData) > 0 {
		if len(matchData) > 64 {
			matchData = matchData[:64]
		}
		evidence["match_data"] = fmt.Sprintf("%x", matchData)
	}

	return &common.Detection{
		ID:        fmt.Sprintf("sig-%d-%d", rule.SID, time.Now().UnixNano()),
		Name:      fmt.Sprintf("Suricata: %s", rule.Msg),
		Type:      common.DetectionSignatureMatch,
		Severity:  severity,
		Certainty: 9, // Signature matches are high certainty.
		MITRE:     mitre,
		SrcIP:     srcIP.String(),
		DstIP:     dstIP.String(),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Timestamp: time.Now(),
		Evidence:  evidence,
	}
}

func classtypeToMITRE(ct string) common.MITRETechnique {
	mapping := map[string]common.MITRETechnique{
		"trojan-activity": {
			TechniqueID: "T1071", TechniqueName: "Application Layer Protocol",
			TacticID: "TA0011", TacticName: "Command and Control",
		},
		"exploit-kit": {
			TechniqueID: "T1203", TechniqueName: "Exploitation for Client Execution",
			TacticID: "TA0002", TacticName: "Execution",
		},
		"web-application-attack": {
			TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing Application",
			TacticID: "TA0001", TacticName: "Initial Access",
		},
		"attempted-admin": {
			TechniqueID: "T1078", TechniqueName: "Valid Accounts",
			TacticID: "TA0004", TacticName: "Privilege Escalation",
		},
		"policy-violation": {
			TechniqueID: "T1071", TechniqueName: "Application Layer Protocol",
			TacticID: "TA0011", TacticName: "Command and Control",
		},
		"misc-attack": {
			TechniqueID: "T1499", TechniqueName: "Endpoint Denial of Service",
			TacticID: "TA0040", TacticName: "Impact",
		},
	}

	if m, ok := mapping[ct]; ok {
		return m
	}
	return common.MITRETechnique{
		TechniqueID: "T1071", TechniqueName: "Application Layer Protocol",
		TacticID: "TA0011", TacticName: "Command and Control",
	}
}
