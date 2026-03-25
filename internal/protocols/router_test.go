package protocols

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// collectingCallback stores metadata for test assertions.
type collectingCallback struct {
	mu       sync.Mutex
	results  []callbackResult
}

type callbackResult struct {
	meta     any
	protocol string
}

func (c *collectingCallback) callback(meta any, protocol string, net, transport gopacket.Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = append(c.results, callbackResult{meta: meta, protocol: protocol})
}

func (c *collectingCallback) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.results)
}

func (c *collectingCallback) get(i int) callbackResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.results[i]
}

func TestRouterHTTPStream(t *testing.T) {
	cb := &collectingCallback{}
	router := NewRouter(cb.callback)

	client := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test/1.0\r\n\r\n")
	server := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello")

	// Create mock flows.
	netFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.ParseIP("192.168.1.100")),
		layers.NewIPEndpoint(net.ParseIP("93.184.216.34")),
	)
	transFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewTCPPortEndpoint(54321),
		layers.NewTCPPortEndpoint(80),
	)

	router.HandleStream(netFlow, transFlow, client, server)

	if cb.count() != 1 {
		t.Fatalf("expected 1 callback, got %d", cb.count())
	}

	result := cb.get(0)
	if result.protocol != "http" {
		t.Errorf("protocol = %q, want http", result.protocol)
	}

	httpMeta, ok := result.meta.(*common.HTTPMeta)
	if !ok {
		t.Fatalf("meta is not *HTTPMeta, got %T", result.meta)
	}
	if httpMeta.Method != "GET" {
		t.Errorf("Method = %q, want GET", httpMeta.Method)
	}
	if httpMeta.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", httpMeta.StatusCode)
	}
}

func TestRouterTLSStream(t *testing.T) {
	cb := &collectingCallback{}
	router := NewRouter(cb.callback)

	// TLS ClientHello: content_type=0x16, version=0x0303 (TLS 1.2), length, handshake_type=0x01
	client := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}

	netFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.ParseIP("192.168.1.100")),
		layers.NewIPEndpoint(net.ParseIP("151.101.1.67")),
	)
	transFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewTCPPortEndpoint(55555),
		layers.NewTCPPortEndpoint(443),
	)

	router.HandleStream(netFlow, transFlow, client, nil)

	if cb.count() != 1 {
		t.Fatalf("expected 1 callback, got %d", cb.count())
	}
	if cb.get(0).protocol != "tls" {
		t.Errorf("protocol = %q, want tls", cb.get(0).protocol)
	}
}

func TestRouterDNSPacket(t *testing.T) {
	cb := &collectingCallback{}
	router := NewRouter(cb.callback)

	// Build a DNS query packet.
	pkt := buildDNSPacket("example.com", 42)
	router.HandlePacket(pkt)

	if cb.count() != 1 {
		t.Fatalf("expected 1 callback, got %d", cb.count())
	}

	result := cb.get(0)
	if result.protocol != "dns" {
		t.Errorf("protocol = %q, want dns", result.protocol)
	}

	dnsMeta, ok := result.meta.(*common.DNSMeta)
	if !ok {
		t.Fatalf("meta is not *DNSMeta, got %T", result.meta)
	}
	if dnsMeta.Query != "example.com" {
		t.Errorf("Query = %q, want example.com", dnsMeta.Query)
	}
}

func TestRouterUnknownStream(t *testing.T) {
	cb := &collectingCallback{}
	router := NewRouter(cb.callback)

	// Random binary data on a non-standard port.
	client := []byte{0x00, 0x01, 0x02, 0x03, 0x04}

	netFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.ParseIP("10.0.0.1")),
		layers.NewIPEndpoint(net.ParseIP("10.0.0.2")),
	)
	transFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewTCPPortEndpoint(12345),
		layers.NewTCPPortEndpoint(9999),
	)

	router.HandleStream(netFlow, transFlow, client, nil)

	// Unknown streams don't trigger callback.
	if cb.count() != 0 {
		t.Errorf("expected 0 callbacks for unknown, got %d", cb.count())
	}

	stats := router.Stats()
	if stats.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", stats.Unknown)
	}
}

func TestRouterStats(t *testing.T) {
	cb := &collectingCallback{}
	router := NewRouter(cb.callback)

	// Send HTTP, TLS, DNS, and unknown.
	httpClient := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	httpServer := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	tlsClient := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	unknown := []byte{0xDE, 0xAD}

	nf, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.ParseIP("10.0.0.1")),
		layers.NewIPEndpoint(net.ParseIP("10.0.0.2")),
	)
	tf80, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(1000), layers.NewTCPPortEndpoint(80))
	tf443, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(1001), layers.NewTCPPortEndpoint(443))
	tfOther, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(1002), layers.NewTCPPortEndpoint(9999))

	router.HandleStream(nf, tf80, httpClient, httpServer)
	router.HandleStream(nf, tf443, tlsClient, nil)
	router.HandleStream(nf, tfOther, unknown, nil)
	router.HandlePacket(buildDNSPacket("test.com", 1))

	stats := router.Stats()
	if stats.HTTP != 1 {
		t.Errorf("HTTP = %d, want 1", stats.HTTP)
	}
	if stats.TLS != 1 {
		t.Errorf("TLS = %d, want 1", stats.TLS)
	}
	if stats.DNS != 1 {
		t.Errorf("DNS = %d, want 1", stats.DNS)
	}
	if stats.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", stats.Unknown)
	}
}

func TestRouterHTTPOnPort8080(t *testing.T) {
	cb := &collectingCallback{}
	router := NewRouter(cb.callback)

	client := []byte("POST /api HTTP/1.1\r\nHost: api.local:8080\r\nContent-Length: 0\r\n\r\n")
	server := []byte("HTTP/1.1 204 No Content\r\n\r\n")

	nf, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.ParseIP("10.0.0.1")),
		layers.NewIPEndpoint(net.ParseIP("10.0.0.2")),
	)
	tf, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(44444), layers.NewTCPPortEndpoint(8080))

	router.HandleStream(nf, tf, client, server)

	if cb.count() != 1 {
		t.Fatalf("expected 1 callback, got %d", cb.count())
	}
	if cb.get(0).protocol != "http" {
		t.Errorf("protocol = %q, want http", cb.get(0).protocol)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildDNSPacket(domain string, txID uint16) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.168.1.100").To4(),
		DstIP:    net.ParseIP("8.8.8.8").To4(),
	}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{
		ID: txID, QR: false, RD: true, QDCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte(domain), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, udp, dns)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: false})
	pkt.Metadata().CaptureInfo.Timestamp = time.Now()
	return pkt
}
