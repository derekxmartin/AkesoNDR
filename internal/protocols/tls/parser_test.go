package tls

import (
	"strings"
	"testing"
)

// buildClientHello builds a minimal TLS 1.2 ClientHello with SNI.
func buildClientHello(sni string, ciphers []uint16, extensions []uint16) []byte {
	// Build extensions data.
	var extData []byte

	// SNI extension.
	if sni != "" {
		sniBytes := []byte(sni)
		sniExt := make([]byte, 0, 9+len(sniBytes))
		sniExt = append(sniExt, 0x00, 0x00) // type: SNI
		sniExtLen := 5 + len(sniBytes)
		sniExt = append(sniExt, byte(sniExtLen>>8), byte(sniExtLen)) // ext data length
		sniListLen := 3 + len(sniBytes)
		sniExt = append(sniExt, byte(sniListLen>>8), byte(sniListLen)) // list length
		sniExt = append(sniExt, 0x00) // host name type
		sniExt = append(sniExt, byte(len(sniBytes)>>8), byte(len(sniBytes))) // name length
		sniExt = append(sniExt, sniBytes...)
		extData = append(extData, sniExt...)
	}

	// Other extensions (just type + empty data).
	for _, ext := range extensions {
		extData = append(extData, byte(ext>>8), byte(ext), 0x00, 0x00)
	}

	// Build cipher suites.
	csData := make([]byte, 0, 2+len(ciphers)*2)
	csLen := len(ciphers) * 2
	csData = append(csData, byte(csLen>>8), byte(csLen))
	for _, c := range ciphers {
		csData = append(csData, byte(c>>8), byte(c))
	}

	// Build handshake body: version(2) + random(32) + session_id_len(1) + ciphers + comp(2) + extensions
	var hsBody []byte
	hsBody = append(hsBody, 0x03, 0x03) // TLS 1.2
	hsBody = append(hsBody, make([]byte, 32)...) // random
	hsBody = append(hsBody, 0x00) // session ID length = 0
	hsBody = append(hsBody, csData...)
	hsBody = append(hsBody, 0x01, 0x00) // compression methods: null
	extLen := len(extData)
	hsBody = append(hsBody, byte(extLen>>8), byte(extLen))
	hsBody = append(hsBody, extData...)

	// Handshake header: type(1) + length(3)
	hsLen := len(hsBody)
	var handshake []byte
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	handshake = append(handshake, hsBody...)

	// TLS record header: type(1) + version(2) + length(2)
	recLen := len(handshake)
	var record []byte
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 in record layer
	record = append(record, byte(recLen>>8), byte(recLen))
	record = append(record, handshake...)

	return record
}

// buildServerHello builds a minimal TLS 1.2 ServerHello.
func buildServerHello(cipher uint16) []byte {
	var hsBody []byte
	hsBody = append(hsBody, 0x03, 0x03) // TLS 1.2
	hsBody = append(hsBody, make([]byte, 32)...) // random
	hsBody = append(hsBody, 0x00) // session ID length = 0
	hsBody = append(hsBody, byte(cipher>>8), byte(cipher))
	hsBody = append(hsBody, 0x00) // compression: null

	hsLen := len(hsBody)
	var handshake []byte
	handshake = append(handshake, 0x02) // ServerHello
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	handshake = append(handshake, hsBody...)

	recLen := len(handshake)
	var record []byte
	record = append(record, 0x16)
	record = append(record, 0x03, 0x03)
	record = append(record, byte(recLen>>8), byte(recLen))
	record = append(record, handshake...)

	return record
}

func TestParseTLSClientHello(t *testing.T) {
	p := NewParser()
	client := buildClientHello("example.com", []uint16{0xc02f, 0xc030, 0x009c}, nil)

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}

	if meta.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com", meta.ServerName)
	}
	if meta.JA3 == "" {
		t.Error("JA3 is empty")
	}
	if len(meta.JA3) != 32 {
		t.Errorf("JA3 length = %d, want 32 (MD5 hex)", len(meta.JA3))
	}
}

func TestParseTLSFullHandshake(t *testing.T) {
	p := NewParser()
	client := buildClientHello("secure.example.com", []uint16{0xc02f, 0x1301}, nil)
	server := buildServerHello(0xc02f) // ECDHE_RSA_AES_128_GCM_SHA256

	meta := p.Parse(client, server)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}

	if meta.ServerName != "secure.example.com" {
		t.Errorf("ServerName = %q", meta.ServerName)
	}
	if meta.Version != "TLS 1.2" {
		t.Errorf("Version = %q, want TLS 1.2", meta.Version)
	}
	if !strings.Contains(meta.Cipher, "ECDHE_RSA") {
		t.Errorf("Cipher = %q, expected ECDHE_RSA variant", meta.Cipher)
	}
	if !meta.Established {
		t.Error("Established should be true")
	}
	if meta.JA3 == "" {
		t.Error("JA3 is empty")
	}
	if meta.JA3S == "" {
		t.Error("JA3S is empty")
	}
}

func TestCanParse(t *testing.T) {
	p := NewParser()

	ch := buildClientHello("test.com", []uint16{0xc02f}, nil)
	if !p.CanParse(ch) {
		t.Error("CanParse should be true for ClientHello")
	}

	if p.CanParse([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("CanParse should be false for HTTP")
	}

	if p.CanParse(nil) {
		t.Error("CanParse should be false for nil")
	}
}

func TestJA3Deterministic(t *testing.T) {
	p := NewParser()

	// Same ClientHello should produce same JA3.
	client := buildClientHello("test.com", []uint16{0xc02f, 0xc030}, nil)
	meta1 := p.Parse(client, nil)
	meta2 := p.Parse(client, nil)

	if meta1 == nil || meta2 == nil {
		t.Fatal("Parse returned nil")
	}
	if meta1.JA3 != meta2.JA3 {
		t.Errorf("JA3 not deterministic: %q vs %q", meta1.JA3, meta2.JA3)
	}
}

func TestJA3DifferentCiphers(t *testing.T) {
	p := NewParser()

	c1 := buildClientHello("test.com", []uint16{0xc02f, 0xc030}, nil)
	c2 := buildClientHello("test.com", []uint16{0x1301, 0x1302}, nil)

	m1 := p.Parse(c1, nil)
	m2 := p.Parse(c2, nil)

	if m1 == nil || m2 == nil {
		t.Fatal("Parse returned nil")
	}
	if m1.JA3 == m2.JA3 {
		t.Error("Different cipher suites should produce different JA3")
	}
}

func TestNonTLSData(t *testing.T) {
	p := NewParser()

	meta := p.Parse([]byte{0x00, 0x01, 0x02, 0x03}, nil)
	if meta != nil {
		t.Error("expected nil for non-TLS data")
	}
}
