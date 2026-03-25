// Package detect — tactic_weight.go implements MITRE ATT&CK tactic
// progression weighting for the host scoring engine.
//
// Hosts showing multi-stage attack progression (recon → credential access
// → lateral movement → exfiltration) score higher than hosts with isolated
// detections. This mirrors how real attacks unfold and prioritizes hosts
// that show kill-chain progression.
package detect

// TacticStage assigns a numeric stage to each MITRE ATT&CK tactic.
// Later stages in the kill chain receive higher weight. A host that
// progresses through multiple stages is more likely under active attack.
var TacticStage = map[string]int{
	"TA0043": 1, // Reconnaissance
	"TA0001": 2, // Initial Access
	"TA0002": 3, // Execution
	"TA0003": 3, // Persistence
	"TA0004": 4, // Privilege Escalation
	"TA0005": 3, // Defense Evasion
	"TA0006": 5, // Credential Access
	"TA0007": 4, // Discovery
	"TA0008": 7, // Lateral Movement
	"TA0009": 6, // Collection
	"TA0010": 8, // Exfiltration
	"TA0011": 6, // Command and Control
	"TA0040": 9, // Impact
}

// TacticProgressionMultiplier computes a multiplier based on how many
// distinct kill-chain stages a host has observed. More stages = higher
// multiplier, indicating a more complete attack chain.
//
//	1 stage  → 1.0x (baseline)
//	2 stages → 1.3x
//	3 stages → 1.6x
//	4+ stages → 2.0x+ (capped at 3.0x)
func TacticProgressionMultiplier(tacticIDs []string) float64 {
	stages := make(map[int]bool)
	for _, tid := range tacticIDs {
		if stage, ok := TacticStage[tid]; ok {
			stages[stage] = true
		}
	}

	n := len(stages)
	switch {
	case n <= 1:
		return 1.0
	case n == 2:
		return 1.3
	case n == 3:
		return 1.6
	case n == 4:
		return 2.0
	case n == 5:
		return 2.5
	default:
		return 3.0
	}
}

// MaxTacticStage returns the highest kill-chain stage observed.
// Used to weight later-stage detections more heavily.
func MaxTacticStage(tacticIDs []string) int {
	maxStage := 0
	for _, tid := range tacticIDs {
		if stage, ok := TacticStage[tid]; ok && stage > maxStage {
			maxStage = stage
		}
	}
	return maxStage
}
