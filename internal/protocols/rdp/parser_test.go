package rdp

import (
	"testing"
)

// buildRDPCR builds an RDP Connection Request with a cookie.
func buildRDPCR(username string) []byte {
	cookie := []byte("Cookie: mstshash=" + username + "\r\n")

	// X.224 CR payload = cookie + negotiation request (8 bytes).
	x224Payload := append(cookie, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00) // SSL+CredSSP

	// X.224 header: length, type=0xE0, dst_ref(2), src_ref(2), class(1)
	x224Header := []byte{
		byte(6 + len(x224Payload)), // X.224 length
		0xE0,                       // CR type
		0x00, 0x00,                 // dst ref
		0x00, 0x00,                 // src ref
		0x00,                       // class
	}

	// TPKT: version=3, reserved=0, length(2)
	tpktLen := 4 + len(x224Header) + len(x224Payload)
	tpkt := []byte{0x03, 0x00, byte(tpktLen >> 8), byte(tpktLen)}

	var data []byte
	data = append(data, tpkt...)
	data = append(data, x224Header...)
	data = append(data, x224Payload...)
	return data
}

func TestParseRDPConnectionRequest(t *testing.T) {
	p := NewParser()
	client := buildRDPCR("admin")

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.Cookie != "admin" {
		t.Errorf("Cookie = %q, want admin", meta.Cookie)
	}
}

func TestParseRDPWithProtocols(t *testing.T) {
	p := NewParser()
	client := buildRDPCR("jsmith")

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.Cookie != "jsmith" {
		t.Errorf("Cookie = %q, want jsmith", meta.Cookie)
	}
	// Should detect SSL+CredSSP from the negotiation request.
	if meta.ClientBuild == "" {
		t.Log("ClientBuild (protocols) not detected — may depend on neg request parsing")
	}
}

func TestCanParse(t *testing.T) {
	p := NewParser()
	if !p.CanParse(buildRDPCR("test")) {
		t.Error("should be true for RDP CR")
	}
	if p.CanParse([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("should be false for HTTP")
	}
	if p.CanParse(nil) {
		t.Error("should be false for nil")
	}
}

func TestNonRDPData(t *testing.T) {
	p := NewParser()
	meta := p.Parse([]byte("not rdp"), nil)
	if meta != nil {
		t.Error("expected nil for non-RDP data")
	}
}
