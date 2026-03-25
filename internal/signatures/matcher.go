package signatures

import (
	"bytes"
	"strings"
)

// Matcher evaluates Suricata rules against packet/session data.
type Matcher struct{}

// NewMatcher creates a content matcher.
func NewMatcher() *Matcher {
	return &Matcher{}
}

// MatchRule evaluates a single rule against the provided payload data.
// clientData is originator→responder, serverData is responder→originator.
// Returns a MatchResult indicating whether the rule matched.
func (m *Matcher) MatchRule(rule *Rule, clientData, serverData []byte) MatchResult {
	result := MatchResult{Rule: rule}

	if !rule.Enabled {
		return result
	}

	// Determine which data to search based on flow direction.
	searchData := selectData(rule, clientData, serverData)
	if len(searchData) == 0 && len(rule.Contents) > 0 {
		return result
	}

	// All content matches must succeed (AND logic).
	if len(rule.Contents) > 0 {
		matched, matchData := matchAllContents(rule.Contents, searchData)
		if !matched {
			return result
		}
		result.MatchData = matchData
	}

	result.Matched = true
	return result
}

// MatchRules evaluates all rules against the data, returning matches.
func (m *Matcher) MatchRules(rules []*Rule, clientData, serverData []byte) []MatchResult {
	var results []MatchResult
	for _, rule := range rules {
		r := m.MatchRule(rule, clientData, serverData)
		if r.Matched {
			results = append(results, r)
		}
	}
	return results
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func selectData(rule *Rule, clientData, serverData []byte) []byte {
	if rule.Flow.ToServer {
		return clientData
	}
	if rule.Flow.ToClient {
		return serverData
	}
	// No flow specified — search both (concatenated).
	combined := make([]byte, 0, len(clientData)+len(serverData))
	combined = append(combined, clientData...)
	combined = append(combined, serverData...)
	return combined
}

// matchAllContents checks that all content matches in a rule are satisfied.
// Returns true if all match, plus the first match data for evidence.
func matchAllContents(contents []ContentMatch, data []byte) (bool, []byte) {
	var firstMatch []byte
	searchStart := 0

	for _, cm := range contents {
		matched, matchPos := matchSingleContent(cm, data, searchStart)
		if cm.Negate {
			if matched {
				return false, nil // negated content was found — rule fails
			}
			continue
		}
		if !matched {
			return false, nil
		}
		if firstMatch == nil && matchPos >= 0 {
			end := matchPos + len(cm.Pattern)
			if end > len(data) {
				end = len(data)
			}
			firstMatch = data[matchPos:end]
		}
		// Update search start for distance/within on next content.
		if matchPos >= 0 {
			searchStart = matchPos + len(cm.Pattern)
		}
	}
	return true, firstMatch
}

// matchSingleContent evaluates one content match against data.
// Returns whether it matched and the position of the match.
func matchSingleContent(cm ContentMatch, data []byte, prevEnd int) (bool, int) {
	pattern := cm.Pattern
	searchData := data

	// Apply offset — absolute position from start of data.
	start := cm.Offset
	if cm.Distance > 0 && prevEnd > 0 {
		start = prevEnd + cm.Distance
	}
	if start > 0 {
		if start >= len(searchData) {
			return false, -1
		}
		searchData = searchData[start:]
	}

	// Apply depth/within — limit how far to search.
	limit := len(searchData)
	if cm.Depth > 0 {
		if cm.Depth < limit {
			limit = cm.Depth
		}
	}
	if cm.Within > 0 && cm.Within < limit {
		limit = cm.Within
	}
	if limit > len(searchData) {
		limit = len(searchData)
	}
	searchData = searchData[:limit]

	// Perform the search.
	var pos int
	if cm.Nocase {
		pos = indexNoCase(searchData, pattern)
	} else {
		pos = bytes.Index(searchData, pattern)
	}

	if pos < 0 {
		return false, -1
	}

	return true, start + pos
}

// indexNoCase performs a case-insensitive search for pattern in data.
func indexNoCase(data, pattern []byte) int {
	if len(pattern) == 0 {
		return 0
	}
	if len(data) < len(pattern) {
		return -1
	}

	lower := []byte(strings.ToLower(string(data)))
	lowerPat := []byte(strings.ToLower(string(pattern)))
	return bytes.Index(lower, lowerPat)
}
