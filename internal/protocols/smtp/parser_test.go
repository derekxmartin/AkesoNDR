package smtp

import (
	"testing"
)

func TestParseSMTPSession(t *testing.T) {
	p := NewParser()
	client := []byte("EHLO mail.example.com\r\nMAIL FROM:<alice@example.com>\r\nRCPT TO:<bob@corp.com>\r\nRCPT TO:<carol@corp.com>\r\nDATA\r\nSubject: Meeting Tomorrow\r\nCc: dave@corp.com\r\n\r\nHello, let's meet.\r\n.\r\nQUIT\r\n")
	server := []byte("220 smtp.corp.com ESMTP\r\n250 OK\r\n")

	meta := p.Parse(client, server)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.From != "alice@example.com" {
		t.Errorf("From = %q", meta.From)
	}
	if len(meta.To) != 2 {
		t.Fatalf("To length = %d, want 2", len(meta.To))
	}
	if meta.To[0] != "bob@corp.com" {
		t.Errorf("To[0] = %q", meta.To[0])
	}
	if meta.Subject != "Meeting Tomorrow" {
		t.Errorf("Subject = %q", meta.Subject)
	}
	if len(meta.CC) != 1 || meta.CC[0] != "dave@corp.com" {
		t.Errorf("CC = %v", meta.CC)
	}
}

func TestParseSMTPWithSTARTTLS(t *testing.T) {
	p := NewParser()
	client := []byte("EHLO client.example.com\r\nSTARTTLS\r\n")
	server := []byte("220 smtp.example.com ESMTP\r\n250-STARTTLS\r\n220 Ready\r\n")

	meta := p.Parse(client, server)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if !meta.TLS {
		t.Error("TLS should be true when STARTTLS is present")
	}
}

func TestParseSMTPWithAuthResults(t *testing.T) {
	p := NewParser()
	client := []byte("EHLO sender.example.com\r\nMAIL FROM:<test@example.com>\r\nRCPT TO:<user@corp.com>\r\nDATA\r\nAuthentication-Results: mx.corp.com; dkim=pass; spf=pass; dmarc=pass\r\nDKIM-Signature: v=1; a=rsa-sha256; d=example.com\r\nSubject: Test\r\n\r\nBody\r\n.\r\n")
	server := []byte("220 mx.corp.com\r\n")

	meta := p.Parse(client, server)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.DKIMStatus != "pass" {
		t.Errorf("DKIMStatus = %q, want pass", meta.DKIMStatus)
	}
	if meta.SPFStatus != "pass" {
		t.Errorf("SPFStatus = %q, want pass", meta.SPFStatus)
	}
	if meta.DMARCStatus != "pass" {
		t.Errorf("DMARCStatus = %q, want pass", meta.DMARCStatus)
	}
}

func TestCanParse(t *testing.T) {
	p := NewParser()
	if !p.CanParse([]byte("EHLO mail.example.com\r\n")) {
		t.Error("should be true for EHLO")
	}
	if !p.CanParse([]byte("HELO mail.example.com\r\n")) {
		t.Error("should be true for HELO")
	}
	if !p.CanParse([]byte("MAIL FROM:<user@example.com>\r\n")) {
		t.Error("should be true for MAIL FROM")
	}
	if p.CanParse([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("should be false for HTTP")
	}
}

func TestNonSMTPData(t *testing.T) {
	p := NewParser()
	meta := p.Parse([]byte("random data"), nil)
	if meta != nil {
		t.Error("expected nil for non-SMTP data")
	}
}
