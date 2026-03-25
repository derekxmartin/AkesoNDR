package signatures

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseRule parses a single Suricata rule string into a Rule struct.
// Returns an error if the rule is malformed.
func ParseRule(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil // comment or blank line
	}

	rule := &Rule{
		Raw:      line,
		Enabled:  true,
		Metadata: make(map[string]string),
	}

	// Split header from options: "action proto src port dir dst port (options)"
	parenIdx := strings.Index(line, "(")
	if parenIdx < 0 {
		return nil, fmt.Errorf("no options section found in rule")
	}

	header := strings.TrimSpace(line[:parenIdx])
	optionsRaw := strings.TrimSpace(line[parenIdx:])
	optionsRaw = strings.TrimPrefix(optionsRaw, "(")
	optionsRaw = strings.TrimSuffix(optionsRaw, ")")

	// Parse header: action protocol src_addr src_port direction dst_addr dst_port
	if err := parseHeader(header, rule); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}

	// Parse options.
	if err := parseOptions(optionsRaw, rule); err != nil {
		return nil, fmt.Errorf("options: %w", err)
	}

	if rule.SID == 0 {
		return nil, fmt.Errorf("rule missing sid")
	}

	return rule, nil
}

// ParseRules parses multiple rules from a string (one per line).
// Skips comments and blank lines. Returns successfully parsed rules
// and any errors encountered.
func ParseRules(text string) ([]*Rule, []error) {
	var rules []*Rule
	var errs []error

	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := ParseRule(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", i+1, err))
			continue
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	return rules, errs
}

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

func parseHeader(header string, rule *Rule) error {
	parts := strings.Fields(header)
	if len(parts) < 7 {
		return fmt.Errorf("expected 7 fields, got %d: %q", len(parts), header)
	}

	rule.Action = strings.ToLower(parts[0])
	rule.Protocol = strings.ToLower(parts[1])
	rule.SrcAddr = parts[2]
	rule.SrcPort = parts[3]
	rule.Direction = parts[4]
	rule.DstAddr = parts[5]
	rule.DstPort = parts[6]

	// Validate direction.
	if rule.Direction != "->" && rule.Direction != "<>" {
		return fmt.Errorf("invalid direction %q", rule.Direction)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Options parsing
// ---------------------------------------------------------------------------

func parseOptions(optionsRaw string, rule *Rule) error {
	opts := splitOptions(optionsRaw)
	var currentContent *ContentMatch

	for _, opt := range opts {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}

		key, val := splitKeyValue(opt)
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch key {
		case "msg":
			rule.Msg = unquote(val)

		case "sid":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("invalid sid %q: %w", val, err)
			}
			rule.SID = n

		case "rev":
			n, _ := strconv.Atoi(val)
			rule.Rev = n

		case "classtype":
			rule.Classtype = val
			rule.Severity = classtypeSeverity(val)

		case "priority":
			n, _ := strconv.Atoi(val)
			if n > 0 {
				rule.Severity = n
			}

		case "reference":
			rule.Reference = append(rule.Reference, val)

		case "content":
			cm := parseContent(val)
			rule.Contents = append(rule.Contents, cm)
			currentContent = &rule.Contents[len(rule.Contents)-1]

		case "nocase":
			if currentContent != nil {
				currentContent.Nocase = true
			}

		case "offset":
			if currentContent != nil {
				n, _ := strconv.Atoi(val)
				currentContent.Offset = n
			}

		case "depth":
			if currentContent != nil {
				n, _ := strconv.Atoi(val)
				currentContent.Depth = n
			}

		case "distance":
			if currentContent != nil {
				n, _ := strconv.Atoi(val)
				currentContent.Distance = n
			}

		case "within":
			if currentContent != nil {
				n, _ := strconv.Atoi(val)
				currentContent.Within = n
			}

		case "http_uri", "http_header", "http_method", "http_cookie",
			"http_user_agent", "http_host", "http_content_type",
			"dns_query", "tls_sni", "file_data":
			if currentContent != nil {
				currentContent.Buffer = key
			}

		case "flow":
			parseFlow(val, &rule.Flow)

		case "threshold":
			rule.Threshold = parseThreshold(val)

		case "pcre":
			rule.PCREs = append(rule.PCREs, unquote(val))

		case "metadata":
			parseMetadata(val, rule.Metadata)
		}
	}

	return nil
}

// splitOptions splits the options string by semicolons, respecting quoted strings.
func splitOptions(s string) []string {
	var opts []string
	var current strings.Builder
	inQuote := false
	escaped := false

	for _, ch := range s {
		if escaped {
			current.WriteRune(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			current.WriteRune(ch)
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			current.WriteRune(ch)
			continue
		}
		if ch == ';' && !inQuote {
			opts = append(opts, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(ch)
	}
	if current.Len() > 0 {
		opts = append(opts, current.String())
	}
	return opts
}

func splitKeyValue(opt string) (string, string) {
	idx := strings.IndexByte(opt, ':')
	if idx < 0 {
		return opt, ""
	}
	return opt[:idx], opt[idx+1:]
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "\"")
	s = strings.TrimSuffix(s, "\"")
	return s
}

// parseContent parses a content value like "pattern" or !"pattern" with hex escapes.
func parseContent(val string) ContentMatch {
	cm := ContentMatch{}
	val = strings.TrimSpace(val)

	if strings.HasPrefix(val, "!") {
		cm.Negate = true
		val = val[1:]
	}
	val = unquote(val)

	// Convert hex escapes like |41 42 43| to bytes.
	cm.Pattern = decodeContentPattern(val)
	return cm
}

// decodeContentPattern handles Suricata content encoding:
// literal text + |HH HH| hex sequences.
func decodeContentPattern(s string) []byte {
	var result []byte
	i := 0
	for i < len(s) {
		if s[i] == '|' {
			// Find closing pipe.
			end := strings.IndexByte(s[i+1:], '|')
			if end < 0 {
				result = append(result, s[i:]...)
				break
			}
			hexStr := s[i+1 : i+1+end]
			hexBytes := decodeHexBytes(hexStr)
			result = append(result, hexBytes...)
			i = i + 1 + end + 1
		} else {
			result = append(result, s[i])
			i++
		}
	}
	return result
}

func decodeHexBytes(s string) []byte {
	var result []byte
	for _, part := range strings.Fields(s) {
		b, err := strconv.ParseUint(part, 16, 8)
		if err == nil {
			result = append(result, byte(b))
		}
	}
	return result
}

func parseFlow(val string, flow *FlowOpts) {
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		switch part {
		case "to_server":
			flow.ToServer = true
		case "to_client":
			flow.ToClient = true
		case "established":
			flow.Established = true
		case "stateless":
			flow.Stateless = true
		case "from_server":
			flow.ToClient = true
		case "from_client":
			flow.ToServer = true
		}
	}
}

func parseThreshold(val string) *ThresholdOpts {
	t := &ThresholdOpts{}
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, " ", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "type":
			t.Type = strings.TrimSpace(kv[1])
		case "track":
			t.Track = strings.TrimSpace(kv[1])
		case "count":
			t.Count, _ = strconv.Atoi(strings.TrimSpace(kv[1]))
		case "seconds":
			t.Seconds, _ = strconv.Atoi(strings.TrimSpace(kv[1]))
		}
	}
	return t
}

func parseMetadata(val string, m map[string]string) {
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, " ", 2)
		if len(kv) == 2 {
			m[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		} else if len(kv) == 1 {
			m[kv[0]] = ""
		}
	}
}

func classtypeSeverity(ct string) int {
	high := map[string]bool{
		"trojan-activity": true, "exploit-kit": true,
		"web-application-attack": true, "attempted-admin": true,
	}
	med := map[string]bool{
		"policy-violation": true, "misc-attack": true,
		"attempted-user": true, "bad-unknown": true,
	}
	if high[ct] {
		return 1
	}
	if med[ct] {
		return 2
	}
	return 3
}
