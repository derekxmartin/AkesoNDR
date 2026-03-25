// +build ignore

// gen_test_pcap.go generates a test PCAP with DNS and HTTP traffic
// for validating the AkesoNDR capture pipeline.
//
// Usage: go run scripts/gen_test_pcap.go
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	path := "tests/pcaps/test.pcap"
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		fmt.Fprintf(os.Stderr, "header: %v\n", err)
		os.Exit(1)
	}

	ts := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	count := 0

	// --- DNS query + response (UDP) ---
	for i := 0; i < 5; i++ {
		// Query: client → DNS server
		query := buildUDP(
			"192.168.1.100", "8.8.8.8", uint16(40000+i), 53,
			dnsQuery(fmt.Sprintf("example%d.com", i), uint16(i)),
			ts.Add(time.Duration(i)*time.Second),
		)
		writePacket(w, query, ts.Add(time.Duration(i)*time.Second))
		count++

		// Response: DNS server → client
		resp := buildUDP(
			"8.8.8.8", "192.168.1.100", 53, uint16(40000+i),
			dnsResponse(fmt.Sprintf("example%d.com", i), uint16(i)),
			ts.Add(time.Duration(i)*time.Second+500*time.Millisecond),
		)
		writePacket(w, resp, ts.Add(time.Duration(i)*time.Second+500*time.Millisecond))
		count++
	}

	// --- TCP 3-way handshake + HTTP GET + response + FIN ---
	clientIP := "192.168.1.100"
	serverIP := "93.184.216.34"
	clientPort := uint16(54321)
	serverPort := uint16(80)
	httpBase := ts.Add(10 * time.Second)

	// SYN
	writePacket(w, buildTCP(clientIP, serverIP, clientPort, serverPort, true, false, false, false, nil, httpBase), httpBase)
	count++
	// SYN-ACK
	writePacket(w, buildTCP(serverIP, clientIP, serverPort, clientPort, true, true, false, false, nil, httpBase.Add(10*time.Millisecond)), httpBase.Add(10*time.Millisecond))
	count++
	// ACK
	writePacket(w, buildTCP(clientIP, serverIP, clientPort, serverPort, false, true, false, false, nil, httpBase.Add(20*time.Millisecond)), httpBase.Add(20*time.Millisecond))
	count++

	// HTTP GET request
	httpReq := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: AkesoNDR-Test/1.0\r\nAccept: */*\r\n\r\n")
	writePacket(w, buildTCP(clientIP, serverIP, clientPort, serverPort, false, true, false, false, httpReq, httpBase.Add(30*time.Millisecond)), httpBase.Add(30*time.Millisecond))
	count++

	// HTTP 200 response
	httpResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\n<html><body>Hello AkesoNDR!</body></html>\r\n")
	writePacket(w, buildTCP(serverIP, clientIP, serverPort, clientPort, false, true, false, false, httpResp, httpBase.Add(50*time.Millisecond)), httpBase.Add(50*time.Millisecond))
	count++

	// FIN from client
	writePacket(w, buildTCP(clientIP, serverIP, clientPort, serverPort, false, true, true, false, nil, httpBase.Add(100*time.Millisecond)), httpBase.Add(100*time.Millisecond))
	count++
	// FIN-ACK from server
	writePacket(w, buildTCP(serverIP, clientIP, serverPort, clientPort, false, true, true, false, nil, httpBase.Add(110*time.Millisecond)), httpBase.Add(110*time.Millisecond))
	count++

	// --- TLS ClientHello (just a TCP SYN + data to port 443) ---
	tlsBase := ts.Add(20 * time.Second)
	writePacket(w, buildTCP(clientIP, "151.101.1.67", 55555, 443, true, false, false, false, nil, tlsBase), tlsBase)
	count++
	writePacket(w, buildTCP("151.101.1.67", clientIP, 443, 55555, true, true, false, false, nil, tlsBase.Add(10*time.Millisecond)), tlsBase.Add(10*time.Millisecond))
	count++
	writePacket(w, buildTCP(clientIP, "151.101.1.67", 55555, 443, false, true, false, false, []byte{0x16, 0x03, 0x01}, tlsBase.Add(20*time.Millisecond)), tlsBase.Add(20*time.Millisecond))
	count++

	// --- ICMP Echo ---
	icmpBase := ts.Add(30 * time.Second)
	writePacket(w, buildICMP(clientIP, "10.0.0.1", icmpBase), icmpBase)
	count++

	fmt.Printf("Generated %s with %d packets\n", path, count)
}

func writePacket(w *pcapgo.Writer, data []byte, ts time.Time) {
	ci := gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(data),
		Length:        len(data),
	}
	w.WritePacket(ci, data)
}

func buildUDP(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, ts time.Time) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, udp, gopacket.Payload(payload))
	return buf.Bytes()
}

func buildTCP(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack, fin, rst bool, payload []byte, ts time.Time) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn, ACK: ack, FIN: fin, RST: rst,
		Window: 65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	if payload != nil {
		gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, tcp, gopacket.Payload(payload))
	} else {
		gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, tcp)
	}
	return buf.Bytes()
}

func buildICMP(srcIP, dstIP string, ts time.Time) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0), // Echo request
		Id:       1, Seq: 1,
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, icmp, gopacket.Payload([]byte("ping")))
	return buf.Bytes()
}

func dnsQuery(domain string, txID uint16) []byte {
	dns := &layers.DNS{
		ID:      txID,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte(domain), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	buf := gopacket.NewSerializeBuffer()
	dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true})
	return buf.Bytes()
}

func dnsResponse(domain string, txID uint16) []byte {
	dns := &layers.DNS{
		ID:      txID,
		QR:      true,
		OpCode:  layers.DNSOpCodeQuery,
		AA:      true,
		RD:      true,
		RA:      true,
		QDCount: 1,
		ANCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte(domain), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte(domain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   300,
				IP:    net.ParseIP("93.184.216.34").To4(),
			},
		},
	}
	buf := gopacket.NewSerializeBuffer()
	dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true})
	return buf.Bytes()
}
