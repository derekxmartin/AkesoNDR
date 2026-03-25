// Package signatures implements Suricata-compatible rule loading, parsing,
// and evaluation for AkesoNDR's signature-based detection engine.
package signatures

// Rule represents a parsed Suricata-compatible rule.
type Rule struct {
	SID       int      `json:"sid"`
	Rev       int      `json:"rev"`
	Msg       string   `json:"msg"`
	Action    string   `json:"action"`     // alert, drop, pass, reject
	Protocol  string   `json:"protocol"`   // tcp, udp, icmp, ip, http, dns, tls, etc.
	SrcAddr   string   `json:"src_addr"`   // source address/network or "any"
	SrcPort   string   `json:"src_port"`   // source port or "any"
	Direction string   `json:"direction"`  // "->" or "<>"
	DstAddr   string   `json:"dst_addr"`   // destination address/network or "any"
	DstPort   string   `json:"dst_port"`   // destination port or "any"
	Classtype string   `json:"classtype"`  // e.g. "trojan-activity"
	Severity  int      `json:"severity"`   // 1-4 (from classtype or priority)
	Reference []string `json:"reference"`  // ["url,example.com", "cve,2024-1234"]

	// Content match options.
	Contents []ContentMatch `json:"contents"`

	// Flow options.
	Flow FlowOpts `json:"flow"`

	// Threshold/rate limiting.
	Threshold *ThresholdOpts `json:"threshold,omitempty"`

	// PCRE patterns.
	PCREs []string `json:"pcres,omitempty"`

	// Metadata key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`

	// Raw rule text for debugging.
	Raw string `json:"-"`

	// Enabled flag for hot-reload toggling.
	Enabled bool `json:"enabled"`
}

// ContentMatch represents a Suricata "content" keyword with modifiers.
type ContentMatch struct {
	Pattern  []byte `json:"pattern"`
	Nocase   bool   `json:"nocase"`
	Offset   int    `json:"offset"`
	Depth    int    `json:"depth"`
	Distance int    `json:"distance"`
	Within   int    `json:"within"`
	Negate   bool   `json:"negate"` // content:!"pattern"

	// Sticky buffer target.
	Buffer string `json:"buffer"` // "", "http_uri", "http_header", "dns_query", etc.
}

// FlowOpts represents Suricata flow directives.
type FlowOpts struct {
	ToServer    bool `json:"to_server"`
	ToClient    bool `json:"to_client"`
	Established bool `json:"established"`
	Stateless   bool `json:"stateless"`
}

// ThresholdOpts represents threshold/rate limiting.
type ThresholdOpts struct {
	Type    string `json:"type"`    // "threshold", "limit", "both"
	Track   string `json:"track"`   // "by_src", "by_dst"
	Count   int    `json:"count"`
	Seconds int    `json:"seconds"`
}

// MatchResult holds the result of a rule evaluation against traffic.
type MatchResult struct {
	Rule      *Rule
	Matched   bool
	MatchData []byte // The data that matched (for evidence)
}
