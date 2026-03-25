package signatures

import (
	"github.com/akesondr/akeso-ndr/internal/common"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// P7-T1: Rule Parser Tests
// ---------------------------------------------------------------------------

func TestParseRule_BasicAlert(t *testing.T) {
	raw := `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Test Rule"; content:"malware"; nocase; sid:2000001; rev:1; classtype:trojan-activity;)`

	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}

	if rule.SID != 2000001 {
		t.Errorf("SID = %d, want 2000001", rule.SID)
	}
	if rule.Msg != "ET TROJAN Test Rule" {
		t.Errorf("Msg = %q, want %q", rule.Msg, "ET TROJAN Test Rule")
	}
	if rule.Action != "alert" {
		t.Errorf("Action = %q, want alert", rule.Action)
	}
	if rule.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp", rule.Protocol)
	}
	if rule.Direction != "->" {
		t.Errorf("Direction = %q, want ->", rule.Direction)
	}
	if rule.Classtype != "trojan-activity" {
		t.Errorf("Classtype = %q, want trojan-activity", rule.Classtype)
	}
	if rule.Severity != 1 {
		t.Errorf("Severity = %d, want 1 (high)", rule.Severity)
	}
	if len(rule.Contents) != 1 {
		t.Fatalf("Contents count = %d, want 1", len(rule.Contents))
	}
	if string(rule.Contents[0].Pattern) != "malware" {
		t.Errorf("Content pattern = %q, want malware", rule.Contents[0].Pattern)
	}
	if !rule.Contents[0].Nocase {
		t.Error("Content nocase should be true")
	}
}

func TestParseRule_HexContent(t *testing.T) {
	raw := `alert tcp any any -> any any (msg:"Hex Test"; content:"|41 42 43|test"; sid:100; rev:1;)`

	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}

	want := []byte{0x41, 0x42, 0x43, 't', 'e', 's', 't'}
	if string(rule.Contents[0].Pattern) != string(want) {
		t.Errorf("Pattern = %v, want %v", rule.Contents[0].Pattern, want)
	}
}

func TestParseRule_FlowAndThreshold(t *testing.T) {
	raw := `alert http any any -> any any (msg:"HTTP Flow Test"; flow:to_server,established; content:"POST"; http_method; threshold:type limit, track by_src, count 5, seconds 60; sid:200; rev:1;)`

	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}

	if !rule.Flow.ToServer {
		t.Error("Flow.ToServer should be true")
	}
	if !rule.Flow.Established {
		t.Error("Flow.Established should be true")
	}
	if rule.Threshold == nil {
		t.Fatal("Threshold should not be nil")
	}
	if rule.Threshold.Type != "limit" {
		t.Errorf("Threshold.Type = %q, want limit", rule.Threshold.Type)
	}
	if rule.Threshold.Count != 5 {
		t.Errorf("Threshold.Count = %d, want 5", rule.Threshold.Count)
	}
	// Content should have buffer set.
	if rule.Contents[0].Buffer != "http_method" {
		t.Errorf("Content buffer = %q, want http_method", rule.Contents[0].Buffer)
	}
}

func TestParseRule_MultipleContents(t *testing.T) {
	raw := `alert tcp any any -> any any (msg:"Multi Content"; content:"GET"; offset:0; depth:3; content:"/admin"; distance:1; within:20; sid:300; rev:1;)`

	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}

	if len(rule.Contents) != 2 {
		t.Fatalf("Contents count = %d, want 2", len(rule.Contents))
	}

	c0 := rule.Contents[0]
	if c0.Offset != 0 || c0.Depth != 3 {
		t.Errorf("Content[0]: offset=%d depth=%d, want 0,3", c0.Offset, c0.Depth)
	}

	c1 := rule.Contents[1]
	if c1.Distance != 1 || c1.Within != 20 {
		t.Errorf("Content[1]: distance=%d within=%d, want 1,20", c1.Distance, c1.Within)
	}
}

func TestParseRule_NegatedContent(t *testing.T) {
	raw := `alert tcp any any -> any any (msg:"Negate Test"; content:!"safe"; sid:400; rev:1;)`

	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}

	if !rule.Contents[0].Negate {
		t.Error("Content should be negated")
	}
}

func TestParseRule_CommentSkipped(t *testing.T) {
	rule, err := ParseRule("# this is a comment")
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}
	if rule != nil {
		t.Error("Comment should return nil rule")
	}
}

func TestParseRule_InvalidMissingSID(t *testing.T) {
	raw := `alert tcp any any -> any any (msg:"No SID";)`
	_, err := ParseRule(raw)
	if err == nil {
		t.Error("Expected error for rule missing SID")
	}
}

func TestParseRules_MultipleRules(t *testing.T) {
	text := `# ET Open rules
alert tcp any any -> any any (msg:"Rule 1"; content:"test1"; sid:1001; rev:1;)
alert udp any any -> any any (msg:"Rule 2"; content:"test2"; sid:1002; rev:1;)
# Another comment
alert http any any -> any any (msg:"Rule 3"; content:"test3"; sid:1003; rev:1;)
`
	rules, errs := ParseRules(text)
	if len(errs) > 0 {
		t.Errorf("Unexpected errors: %v", errs)
	}
	if len(rules) != 3 {
		t.Errorf("Parsed %d rules, want 3", len(rules))
	}
}

// ---------------------------------------------------------------------------
// P7-T2: Content Matcher Tests
// ---------------------------------------------------------------------------

func TestMatcher_BasicContent(t *testing.T) {
	m := NewMatcher()
	rule := &Rule{
		SID:     1,
		Enabled: true,
		Contents: []ContentMatch{
			{Pattern: []byte("malware")},
		},
	}

	// Match.
	result := m.MatchRule(rule, []byte("this contains malware in payload"), nil)
	if !result.Matched {
		t.Error("Expected match")
	}

	// No match.
	result = m.MatchRule(rule, []byte("this is clean traffic"), nil)
	if result.Matched {
		t.Error("Expected no match")
	}
}

func TestMatcher_NocaseContent(t *testing.T) {
	m := NewMatcher()
	rule := &Rule{
		SID:     2,
		Enabled: true,
		Contents: []ContentMatch{
			{Pattern: []byte("MALWARE"), Nocase: true},
		},
	}

	result := m.MatchRule(rule, []byte("this has Malware here"), nil)
	if !result.Matched {
		t.Error("Nocase match should succeed")
	}
}

func TestMatcher_OffsetDepth(t *testing.T) {
	m := NewMatcher()
	rule := &Rule{
		SID:     3,
		Enabled: true,
		Contents: []ContentMatch{
			{Pattern: []byte("GET"), Offset: 0, Depth: 3},
		},
	}

	result := m.MatchRule(rule, []byte("GET /index.html"), nil)
	if !result.Matched {
		t.Error("Expected match at offset 0 depth 3")
	}

	result = m.MatchRule(rule, []byte("POST GET /index.html"), nil)
	if result.Matched {
		t.Error("GET is not at offset 0, should not match with depth 3")
	}
}

func TestMatcher_NegatedContent(t *testing.T) {
	m := NewMatcher()
	rule := &Rule{
		SID:     4,
		Enabled: true,
		Contents: []ContentMatch{
			{Pattern: []byte("evil"), Negate: true},
		},
	}

	result := m.MatchRule(rule, []byte("this is clean"), nil)
	if !result.Matched {
		t.Error("Negated content not found — should match")
	}

	result = m.MatchRule(rule, []byte("this is evil"), nil)
	if result.Matched {
		t.Error("Negated content found — should not match")
	}
}

func TestMatcher_FlowDirection(t *testing.T) {
	m := NewMatcher()
	rule := &Rule{
		SID:     5,
		Enabled: true,
		Flow:    FlowOpts{ToServer: true},
		Contents: []ContentMatch{
			{Pattern: []byte("request")},
		},
	}

	// In client data — should match.
	result := m.MatchRule(rule, []byte("this is a request"), []byte("response"))
	if !result.Matched {
		t.Error("to_server should match client data")
	}

	// Only in server data — should not match.
	result = m.MatchRule(rule, []byte("clean"), []byte("this is a request"))
	if result.Matched {
		t.Error("to_server should not match server data")
	}
}

func TestMatcher_MultipleContentsAND(t *testing.T) {
	m := NewMatcher()
	rule := &Rule{
		SID:     6,
		Enabled: true,
		Contents: []ContentMatch{
			{Pattern: []byte("GET")},
			{Pattern: []byte("/admin")},
		},
	}

	result := m.MatchRule(rule, []byte("GET /admin/panel"), nil)
	if !result.Matched {
		t.Error("Both contents present — should match")
	}

	result = m.MatchRule(rule, []byte("GET /index.html"), nil)
	if result.Matched {
		t.Error("Second content missing — should not match")
	}
}

// ---------------------------------------------------------------------------
// P7-T3: Loader Tests
// ---------------------------------------------------------------------------

func TestLoader_LoadFromDir(t *testing.T) {
	dir := t.TempDir()

	// Write test rules file.
	rulesContent := `alert tcp any any -> any any (msg:"Test Rule 1"; content:"test"; sid:10001; rev:1;)
alert udp any any -> any any (msg:"Test Rule 2"; content:"dns"; sid:10002; rev:1;)
`
	err := os.WriteFile(filepath.Join(dir, "test.rules"), []byte(rulesContent), 0644)
	if err != nil {
		t.Fatalf("Write rules file: %v", err)
	}

	loader := NewLoader([]string{dir})
	count, errs := loader.Load()
	if len(errs) > 0 {
		t.Errorf("Load errors: %v", errs)
	}
	if count != 2 {
		t.Errorf("Loaded %d rules, want 2", count)
	}

	rules := loader.Rules()
	if len(rules) != 2 {
		t.Errorf("Rules() returned %d, want 2", len(rules))
	}

	// Lookup by SID.
	r, ok := loader.GetRule(10001)
	if !ok {
		t.Error("GetRule(10001) not found")
	}
	if r.Msg != "Test Rule 1" {
		t.Errorf("Rule msg = %q, want 'Test Rule 1'", r.Msg)
	}
}

func TestLoader_HotReload(t *testing.T) {
	dir := t.TempDir()

	// Initial load — empty.
	loader := NewLoader([]string{dir})
	count, _ := loader.Load()
	if count != 0 {
		t.Errorf("Initial load = %d, want 0", count)
	}

	// Write a rule file after initial load.
	rulesContent := `alert tcp any any -> any any (msg:"New Rule"; content:"new"; sid:20001; rev:1;)
`
	err := os.WriteFile(filepath.Join(dir, "new.rules"), []byte(rulesContent), 0644)
	if err != nil {
		t.Fatalf("Write rules file: %v", err)
	}

	// Reload.
	count, errs := loader.Reload()
	if len(errs) > 0 {
		t.Errorf("Reload errors: %v", errs)
	}
	if count != 1 {
		t.Errorf("Reload = %d, want 1", count)
	}

	_, ok := loader.GetRule(20001)
	if !ok {
		t.Error("New rule should be available after reload")
	}
}

func TestLoader_InvalidRulesRejected(t *testing.T) {
	dir := t.TempDir()

	rulesContent := `alert tcp any any -> any any (msg:"Valid"; content:"test"; sid:30001; rev:1;)
this is not a valid rule
alert tcp any any -> any any (msg:"Also Valid"; content:"test2"; sid:30002; rev:1;)
`
	os.WriteFile(filepath.Join(dir, "mixed.rules"), []byte(rulesContent), 0644)

	loader := NewLoader([]string{dir})
	count, errs := loader.Load()

	if count != 2 {
		t.Errorf("Loaded %d, want 2 (valid rules only)", count)
	}
	if len(errs) != 1 {
		t.Errorf("Errors = %d, want 1 (invalid rule)", len(errs))
	}
}

// ---------------------------------------------------------------------------
// P7-T4: Pipeline Tests
// ---------------------------------------------------------------------------

func TestPipeline_MatchProducesDetection(t *testing.T) {
	dir := t.TempDir()
	rulesContent := `alert tcp any any -> any any (msg:"Malware Detected"; content:"malware_payload"; sid:40001; rev:1; classtype:trojan-activity;)
`
	os.WriteFile(filepath.Join(dir, "test.rules"), []byte(rulesContent), 0644)

	loader := NewLoader([]string{dir})
	loader.Load()

	var detections int
	pipeline := NewPipeline(loader, func(d *common.Detection) {
		detections++
		if d.Name != "Suricata: Malware Detected" {
			t.Errorf("Detection name = %q", d.Name)
		}
		if d.Type != common.DetectionSignatureMatch {
			t.Errorf("Detection type = %q, want %q", d.Type, common.DetectionSignatureMatch)
		}
		if d.Certainty != 9 {
			t.Errorf("Certainty = %d, want 9", d.Certainty)
		}
		if d.Evidence["sid"] != "40001" {
			t.Errorf("Evidence SID = %q, want 40001", d.Evidence["sid"])
		}
	})

	pipeline.EvaluateSession(
		net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"),
		12345, 80,
		"tcp",
		[]byte("this has malware_payload in it"),
		nil,
	)

	if detections != 1 {
		t.Errorf("Detections fired = %d, want 1", detections)
	}
}

func TestPipeline_NoMatchCleanTraffic(t *testing.T) {
	dir := t.TempDir()
	rulesContent := `alert tcp any any -> any any (msg:"Evil Content"; content:"evil_c2_beacon"; sid:40002; rev:1;)
`
	os.WriteFile(filepath.Join(dir, "test.rules"), []byte(rulesContent), 0644)

	loader := NewLoader([]string{dir})
	loader.Load()

	var detections int
	pipeline := NewPipeline(loader, func(d *common.Detection) {
		detections++
	})

	pipeline.EvaluateSession(
		net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"),
		12345, 443,
		"tcp",
		[]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\n\r\n<html>clean</html>"),
	)

	if detections != 0 {
		t.Errorf("Detections fired = %d, want 0 (clean traffic)", detections)
	}
}

func TestPipeline_ProtocolFilter(t *testing.T) {
	dir := t.TempDir()
	rulesContent := `alert udp any any -> any any (msg:"UDP Only"; content:"test"; sid:40003; rev:1;)
`
	os.WriteFile(filepath.Join(dir, "test.rules"), []byte(rulesContent), 0644)

	loader := NewLoader([]string{dir})
	loader.Load()

	var detections int
	pipeline := NewPipeline(loader, func(d *common.Detection) {
		detections++
	})

	// TCP session — UDP rule should not apply.
	pipeline.EvaluateSession(
		net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"),
		12345, 80, "tcp",
		[]byte("test"), nil,
	)

	if detections != 0 {
		t.Errorf("UDP rule should not match TCP session")
	}

	// UDP session — should match.
	pipeline.EvaluateSession(
		net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"),
		12345, 53, "udp",
		[]byte("test"), nil,
	)

	if detections != 1 {
		t.Errorf("UDP rule should match UDP session, got %d", detections)
	}
}
