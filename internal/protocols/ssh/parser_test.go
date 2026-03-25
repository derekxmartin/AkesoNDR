package ssh

import (
	"testing"
)

func TestParseVersionStrings(t *testing.T) {
	p := NewParser()
	client := []byte("SSH-2.0-OpenSSH_8.9\r\n")
	server := []byte("SSH-2.0-OpenSSH_9.0p1\r\n")

	meta := p.Parse(client, server)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.Client != "SSH-2.0-OpenSSH_8.9" {
		t.Errorf("Client = %q", meta.Client)
	}
	if meta.Server != "SSH-2.0-OpenSSH_9.0p1" {
		t.Errorf("Server = %q", meta.Server)
	}
	if meta.Version != 2 {
		t.Errorf("Version = %d, want 2", meta.Version)
	}
}

func TestParseSSHv1(t *testing.T) {
	p := NewParser()
	client := []byte("SSH-1.99-PuTTY\r\n")

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.Version != 1 {
		t.Errorf("Version = %d, want 1", meta.Version)
	}
}

func TestCanParse(t *testing.T) {
	p := NewParser()
	if !p.CanParse([]byte("SSH-2.0-OpenSSH_8.9\r\n")) {
		t.Error("should be true for SSH data")
	}
	if p.CanParse([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("should be false for HTTP data")
	}
	if p.CanParse(nil) {
		t.Error("should be false for nil")
	}
}

func TestNonSSHData(t *testing.T) {
	p := NewParser()
	meta := p.Parse([]byte("not ssh"), nil)
	if meta != nil {
		t.Error("expected nil for non-SSH data")
	}
}

func TestHASSHDeterministic(t *testing.T) {
	// Verify that the same KEXINIT produces the same HASSH.
	msg := &kexInitMsg{
		kexAlgs:    []string{"curve25519-sha256", "diffie-hellman-group14-sha256"},
		cipherAlgs: []string{"aes128-ctr", "aes256-ctr"},
		macAlgs:    []string{"hmac-sha2-256"},
		compAlgs:   []string{"none"},
	}
	h1 := computeHASSH(msg)
	h2 := computeHASSH(msg)
	if h1 != h2 {
		t.Errorf("HASSH not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 32 {
		t.Errorf("HASSH length = %d, want 32 (MD5 hex)", len(h1))
	}
}

func TestHASSHDifferentParams(t *testing.T) {
	msg1 := &kexInitMsg{
		kexAlgs: []string{"curve25519-sha256"}, cipherAlgs: []string{"aes128-ctr"},
		macAlgs: []string{"hmac-sha2-256"}, compAlgs: []string{"none"},
	}
	msg2 := &kexInitMsg{
		kexAlgs: []string{"diffie-hellman-group14-sha1"}, cipherAlgs: []string{"aes256-ctr"},
		macAlgs: []string{"hmac-sha1"}, compAlgs: []string{"none"},
	}
	if computeHASSH(msg1) == computeHASSH(msg2) {
		t.Error("different params should produce different HASSH")
	}
}
