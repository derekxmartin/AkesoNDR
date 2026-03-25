package ntlm

import (
	"encoding/binary"
	"testing"
)

// buildNTLMType1 builds a minimal NTLM Negotiate message.
func buildNTLMType1(domain, hostname string) []byte {
	msg := make([]byte, 32+len(domain)+len(hostname))
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmNegotiate)
	binary.LittleEndian.PutUint32(msg[12:16], 0) // flags

	// Domain security buffer at offset 16.
	domOff := 32
	binary.LittleEndian.PutUint16(msg[16:18], uint16(len(domain)))
	binary.LittleEndian.PutUint16(msg[18:20], uint16(len(domain)))
	binary.LittleEndian.PutUint32(msg[20:24], uint32(domOff))
	copy(msg[domOff:], domain)

	// Hostname security buffer at offset 24.
	hostOff := domOff + len(domain)
	binary.LittleEndian.PutUint16(msg[24:26], uint16(len(hostname)))
	binary.LittleEndian.PutUint16(msg[26:28], uint16(len(hostname)))
	binary.LittleEndian.PutUint32(msg[28:32], uint32(hostOff))
	copy(msg[hostOff:], hostname)

	return msg
}

// buildNTLMType3 builds a minimal NTLM Authenticate message with UTF-16LE fields.
func buildNTLMType3(domain, username, hostname string) []byte {
	domBytes := encodeUTF16LE(domain)
	userBytes := encodeUTF16LE(username)
	hostBytes := encodeUTF16LE(hostname)

	// Type 3 has security buffers at fixed offsets.
	// We need at least 88 bytes for the header.
	headerSize := 88
	msg := make([]byte, headerSize+len(domBytes)+len(userBytes)+len(hostBytes))
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmAuthenticate)

	// LmChallengeResponse at 12 (empty).
	// NtChallengeResponse at 20 (empty).
	// DomainName at 28.
	domOff := headerSize
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domBytes)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domBytes)))
	binary.LittleEndian.PutUint32(msg[32:36], uint32(domOff))
	copy(msg[domOff:], domBytes)

	// UserName at 36.
	userOff := domOff + len(domBytes)
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(userBytes)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(userBytes)))
	binary.LittleEndian.PutUint32(msg[40:44], uint32(userOff))
	copy(msg[userOff:], userBytes)

	// Workstation at 44.
	hostOff := userOff + len(userBytes)
	binary.LittleEndian.PutUint16(msg[44:46], uint16(len(hostBytes)))
	binary.LittleEndian.PutUint16(msg[46:48], uint16(len(hostBytes)))
	binary.LittleEndian.PutUint32(msg[48:52], uint32(hostOff))
	copy(msg[hostOff:], hostBytes)

	return msg
}

func encodeUTF16LE(s string) []byte {
	var out []byte
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func TestParseNTLMType1(t *testing.T) {
	p := NewParser()
	client := buildNTLMType1("CORP", "WORKSTATION1")

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.Domain != "CORP" {
		t.Errorf("Domain = %q, want CORP", meta.Domain)
	}
	if meta.Hostname != "WORKSTATION1" {
		t.Errorf("Hostname = %q, want WORKSTATION1", meta.Hostname)
	}
}

func TestParseNTLMType3(t *testing.T) {
	p := NewParser()
	client := buildNTLMType3("CORP", "admin", "WS01")

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.Domain != "CORP" {
		t.Errorf("Domain = %q, want CORP", meta.Domain)
	}
	if meta.Username != "admin" {
		t.Errorf("Username = %q, want admin", meta.Username)
	}
	if meta.Hostname != "WS01" {
		t.Errorf("Hostname = %q, want WS01", meta.Hostname)
	}
	if !meta.Success {
		t.Error("Success should be true for Type 3 with username")
	}
}

func TestCanParse(t *testing.T) {
	p := NewParser()
	if !p.CanParse(buildNTLMType1("D", "H")) {
		t.Error("should be true for NTLM data")
	}
	if p.CanParse([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("should be false for HTTP")
	}
	if p.CanParse(nil) {
		t.Error("should be false for nil")
	}
}

func TestFindInStream(t *testing.T) {
	// Embed NTLM Type 3 inside random data (simulating SMB).
	prefix := []byte("some SMB header data here...")
	ntlmMsg := buildNTLMType3("DOMAIN", "jsmith", "PC01")
	suffix := []byte("...more data")

	stream := append(prefix, ntlmMsg...)
	stream = append(stream, suffix...)

	meta := FindInStream(stream)
	if meta == nil {
		t.Fatal("FindInStream returned nil")
	}
	if meta.Username != "jsmith" {
		t.Errorf("Username = %q, want jsmith", meta.Username)
	}
	if meta.Domain != "DOMAIN" {
		t.Errorf("Domain = %q, want DOMAIN", meta.Domain)
	}
}

func TestNonNTLMData(t *testing.T) {
	p := NewParser()
	meta := p.Parse([]byte("not ntlm data"), nil)
	if meta != nil {
		t.Error("expected nil for non-NTLM data")
	}
}
