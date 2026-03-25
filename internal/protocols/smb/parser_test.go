package smb

import (
	"testing"
)

// buildSMB2NegotiateRequest builds a minimal SMB2 Negotiate request.
func buildSMB2NegotiateRequest() []byte {
	// NetBIOS header (4 bytes) + SMB2 header (64 bytes) + negotiate body
	var data []byte
	// NetBIOS length placeholder.
	data = append(data, 0x00, 0x00, 0x00, 0x00)
	// SMB2 magic.
	data = append(data, 0xFE, 'S', 'M', 'B')
	// Structure size (64).
	data = append(data, 64, 0)
	// Credit charge, status, command (Negotiate=0x0000), etc.
	padding := make([]byte, 58) // fill rest of 64-byte header
	data = append(data, padding...)

	return data
}

// buildSMB1NegotiateRequest builds a minimal SMB1 Negotiate.
func buildSMB1NegotiateRequest() []byte {
	var data []byte
	data = append(data, 0x00, 0x00, 0x00, 0x00) // NetBIOS
	data = append(data, 0xFF, 'S', 'M', 'B')     // SMB1 magic
	data = append(data, 0x72)                     // Negotiate command
	data = append(data, make([]byte, 27)...)      // Rest of header
	return data
}

func TestParseSMB2(t *testing.T) {
	p := NewParser()
	client := buildSMB2NegotiateRequest()

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil for SMB2 data")
	}
	if meta.Version != "SMBv2" {
		t.Errorf("Version = %q, want SMBv2", meta.Version)
	}
	if meta.Action != "negotiate" {
		t.Errorf("Action = %q, want negotiate", meta.Action)
	}
}

func TestParseSMB1(t *testing.T) {
	p := NewParser()
	client := buildSMB1NegotiateRequest()

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil for SMB1 data")
	}
	if meta.Version != "SMBv1" {
		t.Errorf("Version = %q, want SMBv1", meta.Version)
	}
	if meta.Action != "negotiate" {
		t.Errorf("Action = %q, want negotiate", meta.Action)
	}
}

func TestCanParseSMB(t *testing.T) {
	p := NewParser()

	if !p.CanParse(buildSMB2NegotiateRequest()) {
		t.Error("CanParse should be true for SMB2")
	}
	if !p.CanParse(buildSMB1NegotiateRequest()) {
		t.Error("CanParse should be true for SMB1")
	}
	if p.CanParse([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("CanParse should be false for HTTP")
	}
	if p.CanParse(nil) {
		t.Error("CanParse should be false for nil")
	}
}

func TestNonSMBData(t *testing.T) {
	p := NewParser()
	meta := p.Parse([]byte("not SMB data at all"), nil)
	if meta != nil {
		t.Error("expected nil for non-SMB data")
	}
}
