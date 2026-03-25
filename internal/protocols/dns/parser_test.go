package dns

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildDNSQueryPacket creates a synthetic DNS query packet over UDP.
func buildDNSQueryPacket(domain string, qtype layers.DNSType, txID uint16) gopacket.Packet {
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
	udp := &layers.UDP{
		SrcPort: 40000,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{
		ID:      txID,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte(domain), Type: qtype, Class: layers.DNSClassIN},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, udp, dns)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: false})
	pkt.Metadata().CaptureInfo.Timestamp = time.Now()
	return pkt
}

// buildDNSResponsePacket creates a DNS response with an A record.
func buildDNSResponsePacket(domain string, ip4 string, txID uint16, ttl uint32) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("8.8.8.8").To4(),
		DstIP:    net.ParseIP("192.168.1.100").To4(),
	}
	udp := &layers.UDP{
		SrcPort: 53,
		DstPort: 40000,
	}
	udp.SetNetworkLayerForChecksum(ipLayer)
	dns := &layers.DNS{
		ID:           txID,
		QR:           true,
		AA:           true,
		RD:           true,
		RA:           true,
		ResponseCode: layers.DNSResponseCodeNoErr,
		QDCount:      1,
		ANCount:      1,
		Questions: []layers.DNSQuestion{
			{Name: []byte(domain), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte(domain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   ttl,
				IP:    net.ParseIP(ip4).To4(),
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ipLayer, udp, dns)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: false})
	pkt.Metadata().CaptureInfo.Timestamp = time.Now()
	return pkt
}

func TestParseQuery(t *testing.T) {
	p := NewParser()
	pkt := buildDNSQueryPacket("example.com", layers.DNSTypeA, 42)

	meta := p.Parse(pkt)
	if meta == nil {
		t.Fatal("Parse returned nil for DNS query packet")
	}

	if meta.Query != "example.com" {
		t.Errorf("Query = %q, want %q", meta.Query, "example.com")
	}
	if meta.QType != 1 {
		t.Errorf("QType = %d, want 1 (A)", meta.QType)
	}
	if meta.QTypeName != "A" {
		t.Errorf("QTypeName = %q, want %q", meta.QTypeName, "A")
	}
	if meta.QClass != 1 {
		t.Errorf("QClass = %d, want 1 (IN)", meta.QClass)
	}
	if meta.QClassName != "IN" {
		t.Errorf("QClassName = %q, want %q", meta.QClassName, "IN")
	}
	if meta.TransID != 42 {
		t.Errorf("TransID = %d, want 42", meta.TransID)
	}
	if !meta.RD {
		t.Error("RD should be true")
	}
	if meta.Proto != "udp" {
		t.Errorf("Proto = %q, want %q", meta.Proto, "udp")
	}
	if meta.QueryLength != 11 {
		t.Errorf("QueryLength = %d, want 11", meta.QueryLength)
	}
	if meta.SubdomainDepth != 2 {
		t.Errorf("SubdomainDepth = %d, want 2", meta.SubdomainDepth)
	}
	if meta.Entropy <= 0 {
		t.Errorf("Entropy = %f, want > 0", meta.Entropy)
	}
}

func TestParseResponse(t *testing.T) {
	p := NewParser()
	pkt := buildDNSResponsePacket("example.com", "93.184.216.34", 42, 300)

	meta := p.Parse(pkt)
	if meta == nil {
		t.Fatal("Parse returned nil for DNS response packet")
	}

	if meta.TransID != 42 {
		t.Errorf("TransID = %d, want 42", meta.TransID)
	}
	if !meta.AA {
		t.Error("AA should be true")
	}
	if !meta.RD {
		t.Error("RD should be true")
	}
	if !meta.RA {
		t.Error("RA should be true")
	}
	if meta.RCode != 0 {
		t.Errorf("RCode = %d, want 0 (NOERROR)", meta.RCode)
	}
	if meta.RCodeName != "NOERROR" {
		t.Errorf("RCodeName = %q, want %q", meta.RCodeName, "NOERROR")
	}
	if meta.TotalAnswers != 1 {
		t.Errorf("TotalAnswers = %d, want 1", meta.TotalAnswers)
	}
	if len(meta.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(meta.Answers))
	}
	ans := meta.Answers[0]
	if ans.Data != "93.184.216.34" {
		t.Errorf("Answer.Data = %q, want %q", ans.Data, "93.184.216.34")
	}
	if ans.Type != "A" {
		t.Errorf("Answer.Type = %q, want %q", ans.Type, "A")
	}
	if ans.TTL != 300 {
		t.Errorf("Answer.TTL = %d, want 300", ans.TTL)
	}
	if len(meta.TTLs) != 1 || meta.TTLs[0] != 300 {
		t.Errorf("TTLs = %v, want [300]", meta.TTLs)
	}
}

func TestCanParse(t *testing.T) {
	p := NewParser()

	dnsPkt := buildDNSQueryPacket("test.com", layers.DNSTypeA, 1)
	if !p.CanParse(dnsPkt) {
		t.Error("CanParse should be true for DNS packet")
	}

	// Build a non-DNS TCP packet.
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("10.0.0.1").To4(),
		DstIP:    net.ParseIP("10.0.0.2").To4(),
	}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, SYN: true}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp)
	nonDNS := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{})

	if p.CanParse(nonDNS) {
		t.Error("CanParse should be false for non-DNS packet")
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input string
		min   float64
		max   float64
	}{
		{"", 0, 0},
		{"aaaa", 0, 0.001},                               // Single char → entropy 0
		{"abcd", 1.9, 2.1},                                // 4 unique chars → ~2.0 bits
		{"example.com", 2.5, 3.5},                          // Normal domain
		{"aGVsbG8gd29ybGQ.tunnel.evil.com", 3.5, 5.0},     // Base64-like → high entropy
	}

	for _, tt := range tests {
		e := ShannonEntropy(tt.input)
		if e < tt.min || e > tt.max {
			t.Errorf("ShannonEntropy(%q) = %f, want [%f, %f]", tt.input, e, tt.min, tt.max)
		}
	}
}

func TestShannonEntropyKnownValues(t *testing.T) {
	// "ab" has exactly 1.0 bits of entropy (2 unique chars, each p=0.5).
	e := ShannonEntropy("ab")
	if math.Abs(e-1.0) > 0.001 {
		t.Errorf("ShannonEntropy(\"ab\") = %f, want 1.0", e)
	}
}

func TestSubdomainDepth(t *testing.T) {
	tests := []struct {
		domain string
		want   int
	}{
		{"", 0},
		{"com", 1},
		{"example.com", 2},
		{"www.example.com", 3},
		{"a.b.c.d.example.com", 6},
		{"example.com.", 2}, // trailing dot stripped
	}
	for _, tt := range tests {
		got := SubdomainDepth(tt.domain)
		if got != tt.want {
			t.Errorf("SubdomainDepth(%q) = %d, want %d", tt.domain, got, tt.want)
		}
	}
}

func TestParseNXDOMAIN(t *testing.T) {
	// Build an NXDOMAIN response.
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("8.8.8.8").To4(),
		DstIP:    net.ParseIP("192.168.1.100").To4(),
	}
	udp := &layers.UDP{SrcPort: 53, DstPort: 40000}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{
		ID:           99,
		QR:           true,
		ResponseCode: layers.DNSResponseCodeNXDomain,
		QDCount:      1,
		Questions: []layers.DNSQuestion{
			{Name: []byte("doesnotexist.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, udp, dns)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: false})

	p := NewParser()
	meta := p.Parse(pkt)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}

	if meta.RCode != 3 {
		t.Errorf("RCode = %d, want 3 (NXDOMAIN)", meta.RCode)
	}
	if meta.RCodeName != "NXDOMAIN" {
		t.Errorf("RCodeName = %q, want %q", meta.RCodeName, "NXDOMAIN")
	}
	if meta.TotalAnswers != 0 {
		t.Errorf("TotalAnswers = %d, want 0", meta.TotalAnswers)
	}
	if meta.SubdomainDepth != 3 {
		t.Errorf("SubdomainDepth = %d, want 3", meta.SubdomainDepth)
	}
}

func TestParseTXTQuery(t *testing.T) {
	pkt := buildDNSQueryPacket("_dmarc.example.com", layers.DNSTypeTXT, 77)
	p := NewParser()
	meta := p.Parse(pkt)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.QTypeName != "TXT" {
		t.Errorf("QTypeName = %q, want TXT", meta.QTypeName)
	}
	if meta.SubdomainDepth != 3 {
		t.Errorf("SubdomainDepth = %d, want 3", meta.SubdomainDepth)
	}
}
