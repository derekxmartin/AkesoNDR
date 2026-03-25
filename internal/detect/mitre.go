package detect

import "github.com/akesondr/akeso-ndr/internal/common"

// MITRE ATT&CK technique mappings for AkesoNDR detections.

func mitreBeacon() common.MITRETechnique {
	return common.MITRETechnique{
		TechniqueID: "T1071", TechniqueName: "Application Layer Protocol",
		TacticID: "TA0011", TacticName: "Command and Control",
	}
}

func mitreDNSTunnel() common.MITRETechnique {
	return common.MITRETechnique{
		TechniqueID: "T1071.004", TechniqueName: "DNS",
		TacticID: "TA0011", TacticName: "Command and Control",
	}
}

func mitreLateralMovement() common.MITRETechnique {
	return common.MITRETechnique{
		TechniqueID: "T1021", TechniqueName: "Remote Services",
		TacticID: "TA0008", TacticName: "Lateral Movement",
	}
}

func mitreExfiltration() common.MITRETechnique {
	return common.MITRETechnique{
		TechniqueID: "T1041", TechniqueName: "Exfiltration Over C2 Channel",
		TacticID: "TA0010", TacticName: "Exfiltration",
	}
}

func mitrePortScan() common.MITRETechnique {
	return common.MITRETechnique{
		TechniqueID: "T1046", TechniqueName: "Network Service Discovery",
		TacticID: "TA0007", TacticName: "Discovery",
	}
}
