// Package integration contains end-to-end tests that validate the full
// AkesoNDR pipeline: capture → reassemble → dissect → session metadata.
package integration

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/protocols"
)

// result holds one metadata callback result.
type result struct {
	meta     any
	protocol string
	net      gopacket.Flow
	trans    gopacket.Flow
}

// collector gathers all protocol metadata produced during a test.
type collector struct {
	mu      sync.Mutex
	results []result
}

func (c *collector) callback(meta any, protocol string, net, trans gopacket.Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = append(c.results, result{meta, protocol, net, trans})
}

func (c *collector) byProtocol(proto string) []result {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []result
	for _, r := range c.results {
		if r.protocol == proto {
			out = append(out, r)
		}
	}
	return out
}

// TestDNSFromPCAP reads the test PCAP and verifies DNS metadata extraction.
func TestDNSFromPCAP(t *testing.T) {
	coll := &collector{}
	router := protocols.NewRouter(coll.callback)

	packets := readTestPCAP(t)
	if len(packets) == 0 {
		t.Skip("test PCAP has no packets")
	}

	// Feed all packets through the router.
	for _, pkt := range packets {
		router.HandlePacket(pkt)
	}

	dnsResults := coll.byProtocol("dns")
	if len(dnsResults) == 0 {
		t.Fatal("no DNS metadata extracted from test PCAP")
	}

	t.Logf("Extracted %d DNS events from %d packets", len(dnsResults), len(packets))

	// Verify first DNS query metadata.
	first := dnsResults[0]
	dnsMeta, ok := first.meta.(*common.DNSMeta)
	if !ok {
		t.Fatalf("DNS meta is %T, want *common.DNSMeta", first.meta)
	}

	if dnsMeta.Query == "" {
		t.Error("DNS query is empty")
	}
	if dnsMeta.QTypeName == "" {
		t.Error("DNS QTypeName is empty")
	}
	if dnsMeta.Proto == "" {
		t.Error("DNS Proto is empty")
	}
	if dnsMeta.QueryLength <= 0 {
		t.Errorf("DNS QueryLength = %d, want > 0", dnsMeta.QueryLength)
	}
	if dnsMeta.Entropy <= 0 {
		t.Errorf("DNS Entropy = %f, want > 0", dnsMeta.Entropy)
	}

	t.Logf("First DNS: query=%q type=%s proto=%s entropy=%.2f depth=%d",
		dnsMeta.Query, dnsMeta.QTypeName, dnsMeta.Proto, dnsMeta.Entropy, dnsMeta.SubdomainDepth)

	// Verify we got both queries and responses.
	queries := 0
	responses := 0
	for _, r := range dnsResults {
		dm := r.meta.(*common.DNSMeta)
		if dm.TotalAnswers > 0 {
			responses++
		} else {
			queries++
		}
	}
	t.Logf("DNS breakdown: %d queries, %d responses", queries, responses)

	if queries == 0 {
		t.Error("expected at least one DNS query")
	}
	if responses == 0 {
		t.Error("expected at least one DNS response")
	}
}

// TestHTTPFromSynthetic validates HTTP metadata extraction using synthetic
// reassembled stream data passed through the router (since the test PCAP's
// HTTP data requires the TCP reassembly engine which is harder to drive in
// a unit test).
func TestHTTPFromSynthetic(t *testing.T) {
	coll := &collector{}
	router := protocols.NewRouter(coll.callback)

	client := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: AkesoNDR-Test/1.0\r\nAccept: */*\r\n\r\n")
	server := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\n<html><body>Hello AkesoNDR!</body></html>\r\n")

	netFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.IP{192, 168, 1, 100}),
		layers.NewIPEndpoint(net.IP{93, 184, 216, 34}),
	)
	transFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewTCPPortEndpoint(54321),
		layers.NewTCPPortEndpoint(80),
	)

	router.HandleStream(netFlow, transFlow, client, server)

	httpResults := coll.byProtocol("http")
	if len(httpResults) != 1 {
		t.Fatalf("expected 1 HTTP result, got %d", len(httpResults))
	}

	httpMeta, ok := httpResults[0].meta.(*common.HTTPMeta)
	if !ok {
		t.Fatalf("HTTP meta is %T, want *common.HTTPMeta", httpResults[0].meta)
	}

	if httpMeta.Method != "GET" {
		t.Errorf("Method = %q, want GET", httpMeta.Method)
	}
	if httpMeta.URI != "/index.html" {
		t.Errorf("URI = %q, want /index.html", httpMeta.URI)
	}
	if httpMeta.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", httpMeta.Host)
	}
	if httpMeta.UserAgent != "AkesoNDR-Test/1.0" {
		t.Errorf("UserAgent = %q", httpMeta.UserAgent)
	}
	if httpMeta.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", httpMeta.StatusCode)
	}
	if httpMeta.RespMIMETypes != "text/html" {
		t.Errorf("RespMIMETypes = %q, want text/html", httpMeta.RespMIMETypes)
	}
	if httpMeta.ResponseBodyLen <= 0 {
		t.Errorf("ResponseBodyLen = %d, want > 0", httpMeta.ResponseBodyLen)
	}

	t.Logf("HTTP: %s %s → %d %s (req=%d resp=%d bytes)",
		httpMeta.Method, httpMeta.URI, httpMeta.StatusCode, httpMeta.StatusMsg,
		httpMeta.RequestBodyLen, httpMeta.ResponseBodyLen)
}

// TestRouterStatsFromPCAP verifies protocol classification counts.
func TestRouterStatsFromPCAP(t *testing.T) {
	coll := &collector{}
	router := protocols.NewRouter(coll.callback)

	packets := readTestPCAP(t)
	for _, pkt := range packets {
		router.HandlePacket(pkt)
	}

	stats := router.Stats()
	t.Logf("Router stats: DNS=%d HTTP=%d TLS=%d Unknown=%d",
		stats.DNS, stats.HTTP, stats.TLS, stats.Unknown)

	if stats.DNS == 0 {
		t.Error("expected DNS > 0")
	}
}

// TestDNSEntropyFromPCAP verifies entropy values for all DNS queries.
func TestDNSEntropyFromPCAP(t *testing.T) {
	coll := &collector{}
	router := protocols.NewRouter(coll.callback)

	packets := readTestPCAP(t)
	for _, pkt := range packets {
		router.HandlePacket(pkt)
	}

	for _, r := range coll.byProtocol("dns") {
		dm := r.meta.(*common.DNSMeta)
		if dm.Query != "" {
			if dm.Entropy < 0 {
				t.Errorf("Negative entropy for %q: %f", dm.Query, dm.Entropy)
			}
			if dm.SubdomainDepth < 1 {
				t.Errorf("SubdomainDepth < 1 for %q: %d", dm.Query, dm.SubdomainDepth)
			}
			t.Logf("DNS %q: entropy=%.4f depth=%d len=%d",
				dm.Query, dm.Entropy, dm.SubdomainDepth, dm.QueryLength)
		}
	}
}

// TestMultipleHTTPSessions tests parsing multiple HTTP sessions.
func TestMultipleHTTPSessions(t *testing.T) {
	coll := &collector{}
	router := protocols.NewRouter(coll.callback)

	sessions := []struct {
		method string
		uri    string
		status int
	}{
		{"GET", "/", 200},
		{"POST", "/api/users", 201},
		{"GET", "/static/style.css", 200},
		{"DELETE", "/api/sessions/123", 204},
		{"PUT", "/api/config", 200},
	}

	for i, s := range sessions {
		client := []byte(s.method + " " + s.uri + " HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
		server := []byte("HTTP/1.1 " + statusLine(s.status) + "\r\nContent-Length: 0\r\n\r\n")

		nf, _ := gopacket.FlowFromEndpoints(
			layers.NewIPEndpoint(net.IP{10, 0, 0, 1}),
			layers.NewIPEndpoint(net.IP{10, 0, 0, 2}),
		)
		tf, _ := gopacket.FlowFromEndpoints(
			layers.NewTCPPortEndpoint(layers.TCPPort(50000+i)),
			layers.NewTCPPortEndpoint(80),
		)
		router.HandleStream(nf, tf, client, server)
	}

	httpResults := coll.byProtocol("http")
	if len(httpResults) != 5 {
		t.Fatalf("expected 5 HTTP results, got %d", len(httpResults))
	}

	for i, r := range httpResults {
		m := r.meta.(*common.HTTPMeta)
		if m.Method != sessions[i].method {
			t.Errorf("session %d: Method = %q, want %q", i, m.Method, sessions[i].method)
		}
		if m.URI != sessions[i].uri {
			t.Errorf("session %d: URI = %q, want %q", i, m.URI, sessions[i].uri)
		}
		if m.StatusCode != sessions[i].status {
			t.Errorf("session %d: StatusCode = %d, want %d", i, m.StatusCode, sessions[i].status)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func readTestPCAP(t *testing.T) []gopacket.Packet {
	t.Helper()

	path := "../../tests/pcaps/test.pcap"
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open test PCAP: %v", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcapgo.NewReader: %v", err)
	}

	source := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)
	source.DecodeOptions.Lazy = false

	var packets []gopacket.Packet
	for pkt := range source.Packets() {
		packets = append(packets, pkt)
	}

	if len(packets) == 0 {
		t.Fatal("test PCAP contains no packets")
	}
	return packets
}

func statusLine(code int) string {
	switch code {
	case 200:
		return "200 OK"
	case 201:
		return "201 Created"
	case 204:
		return "204 No Content"
	case 404:
		return "404 Not Found"
	default:
		return "200 OK"
	}
}

// Ensure time import is used.
var _ = time.Now
