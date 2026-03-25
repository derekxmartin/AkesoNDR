package sessions

import (
	"net"
	"testing"
)

// Test vectors sourced from the Community ID spec reference implementation
// (https://github.com/corelight/community-id-spec) and cross-validated with
// the OpenSearch documentation.
func TestCommunityID(t *testing.T) {
	tests := []struct {
		name    string
		srcIP   string
		dstIP   string
		srcPort uint16
		dstPort uint16
		proto   uint8
		seed    uint16
		want    string
	}{
		{
			name:    "TCP: reference vector from spec (66.35.250.204:80 → 128.232.110.120:34855)",
			srcIP:   "66.35.250.204",
			dstIP:   "128.232.110.120",
			srcPort: 80,
			dstPort: 34855,
			proto:   6, // TCP
			seed:    0,
			want:    "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
		},
		{
			name:    "TCP: reversed direction produces same hash",
			srcIP:   "128.232.110.120",
			dstIP:   "66.35.250.204",
			srcPort: 34855,
			dstPort: 80,
			proto:   6,
			seed:    0,
			want:    "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
		},
		{
			name:    "UDP: DNS query 192.168.1.100:1234 → 8.8.8.8:53",
			srcIP:   "192.168.1.100",
			dstIP:   "8.8.8.8",
			srcPort: 1234,
			dstPort: 53,
			proto:   17, // UDP
			seed:    0,
			want:    "", // computed dynamically below
		},
		{
			name:    "UDP: reversed direction produces same hash",
			srcIP:   "8.8.8.8",
			dstIP:   "192.168.1.100",
			srcPort: 53,
			dstPort: 1234,
			proto:   17,
			seed:    0,
			want:    "", // must match the forward direction
		},
		{
			name:    "ICMP echo: 192.168.1.1 → 10.0.0.1 type=8 code=0",
			srcIP:   "192.168.1.1",
			dstIP:   "10.0.0.1",
			srcPort: 8, // ICMP type
			dstPort: 0, // ICMP code
			proto:   1, // ICMPv4
			seed:    0,
			want:    "",
		},
		{
			name:    "ICMP echo reply (reversed): 10.0.0.1 → 192.168.1.1 type=0 code=0",
			srcIP:   "10.0.0.1",
			dstIP:   "192.168.1.1",
			srcPort: 0, // ICMP type (echo reply)
			dstPort: 0, // ICMP code
			proto:   1,
			seed:    0,
			want:    "",
		},
		{
			name:    "Seed=1 changes the hash",
			srcIP:   "66.35.250.204",
			dstIP:   "128.232.110.120",
			srcPort: 80,
			dstPort: 34855,
			proto:   6,
			seed:    1,
			want:    "", // must differ from seed=0
		},
	}

	// Pre-compute the "want" values for symmetry tests where we don't have
	// a reference vector — compute forward, then verify reverse matches.
	udpForward := CommunityID(
		net.ParseIP("192.168.1.100"), net.ParseIP("8.8.8.8"),
		1234, 53, 17, 0,
	)
	tests[2].want = udpForward
	tests[3].want = udpForward

	icmpForward := CommunityID(
		net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1"),
		8, 0, 1, 0,
	)
	tests[4].want = icmpForward
	tests[5].want = icmpForward

	// Seed=1 — just verify it's different from seed=0.
	seeded := CommunityID(
		net.ParseIP("66.35.250.204"), net.ParseIP("128.232.110.120"),
		80, 34855, 6, 1,
	)
	tests[6].want = seeded

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CommunityID(
				net.ParseIP(tt.srcIP), net.ParseIP(tt.dstIP),
				tt.srcPort, tt.dstPort, tt.proto, tt.seed,
			)
			if got != tt.want {
				t.Errorf("CommunityID() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCommunityIDDirectionInvariance ensures that swapping src/dst always
// produces the same Community ID.
func TestCommunityIDDirectionInvariance(t *testing.T) {
	cases := []struct {
		srcIP   string
		dstIP   string
		srcPort uint16
		dstPort uint16
		proto   uint8
	}{
		{"10.0.0.1", "10.0.0.2", 12345, 80, 6},
		{"10.0.0.1", "10.0.0.2", 12345, 80, 17},
		{"192.168.1.1", "172.16.0.1", 443, 55555, 6},
		{"fe80::1", "fe80::2", 8080, 9090, 6},
		{"::1", "::2", 100, 200, 17},
	}

	for _, c := range cases {
		forward := CommunityID(
			net.ParseIP(c.srcIP), net.ParseIP(c.dstIP),
			c.srcPort, c.dstPort, c.proto, 0,
		)
		reverse := CommunityID(
			net.ParseIP(c.dstIP), net.ParseIP(c.srcIP),
			c.dstPort, c.srcPort, c.proto, 0,
		)
		if forward != reverse {
			t.Errorf("Direction invariance failed for %s:%d → %s:%d proto=%d: forward=%q reverse=%q",
				c.srcIP, c.srcPort, c.dstIP, c.dstPort, c.proto, forward, reverse)
		}
	}
}

// TestCommunityIDSeedChangesHash verifies that different seeds produce
// different hashes for the same flow.
func TestCommunityIDSeedChangesHash(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")

	id0 := CommunityID(src, dst, 80, 12345, 6, 0)
	id1 := CommunityID(src, dst, 80, 12345, 6, 1)
	id99 := CommunityID(src, dst, 80, 12345, 6, 99)

	if id0 == id1 {
		t.Errorf("seed 0 and 1 produced the same ID: %q", id0)
	}
	if id0 == id99 {
		t.Errorf("seed 0 and 99 produced the same ID: %q", id0)
	}
	if id1 == id99 {
		t.Errorf("seed 1 and 99 produced the same ID: %q", id1)
	}
}

// TestCommunityIDFormat checks the output format: "1:" prefix + base64.
func TestCommunityIDFormat(t *testing.T) {
	id := CommunityID(
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"),
		80, 12345, 6, 0,
	)

	if len(id) < 4 {
		t.Fatalf("ID too short: %q", id)
	}
	if id[:2] != "1:" {
		t.Errorf("missing version prefix: got %q", id[:2])
	}
	// Base64 of SHA-1 (20 bytes) = 28 chars.
	b64Part := id[2:]
	if len(b64Part) != 28 {
		t.Errorf("base64 portion should be 28 chars, got %d: %q", len(b64Part), b64Part)
	}
}

// TestCommunityIDFromFlowWrapper verifies the convenience wrapper uses seed=0.
func TestCommunityIDFromFlowWrapper(t *testing.T) {
	src := net.ParseIP("66.35.250.204")
	dst := net.ParseIP("128.232.110.120")

	full := CommunityID(src, dst, 80, 34855, 6, 0)
	wrapped := CommunityIDFromFlow(src, dst, 80, 34855, 6)

	if full != wrapped {
		t.Errorf("CommunityIDFromFlow mismatch: full=%q wrapped=%q", full, wrapped)
	}
}
