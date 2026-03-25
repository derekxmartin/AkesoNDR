package kerberos

import (
	"testing"
)

// buildASREQ builds a minimal AS-REQ with etypes.
func buildASREQ(etypes []int) []byte {
	// APPLICATION 10 (AS-REQ) = 0x6A
	// We build a minimal ASN.1 structure with an etype sequence.

	// Build etype sequence: SEQUENCE { INTEGER, INTEGER, ... }
	var etypeSeq []byte
	for _, e := range etypes {
		if e < 256 {
			etypeSeq = append(etypeSeq, 0x02, 0x01, byte(e)) // INTEGER, len=1, value
		} else {
			etypeSeq = append(etypeSeq, 0x02, 0x02, byte(e>>8), byte(e)) // INTEGER, len=2
		}
	}
	seqData := append([]byte{0x30, byte(len(etypeSeq))}, etypeSeq...)

	// Wrap in a structure: APPLICATION 10 + SEQUENCE container + body with etype seq
	body := make([]byte, 0, 50+len(seqData))
	// Some padding to simulate real KDC-REQ structure.
	body = append(body, 0x30, 0x82, 0x00, byte(20+len(seqData))) // outer SEQUENCE
	body = append(body, make([]byte, 10)...)                       // filler
	body = append(body, seqData...)
	body = append(body, make([]byte, 10)...) // trailing

	// APPLICATION 10 tag.
	result := []byte{0x6A, byte(len(body))}
	result = append(result, body...)

	return result
}

// buildASREP builds a minimal AS-REP.
func buildASREP() []byte {
	// APPLICATION 11 = 0x6B
	body := make([]byte, 20)
	return append([]byte{0x6B, byte(len(body))}, body...)
}

// buildTGSREQ builds a minimal TGS-REQ.
func buildTGSREQ() []byte {
	// APPLICATION 12 = 0x6C
	body := make([]byte, 20)
	return append([]byte{0x6C, byte(len(body))}, body...)
}

// buildKRBError builds a minimal KRB-ERROR with an error code.
func buildKRBError(code int) []byte {
	// APPLICATION 30 = 0x7E
	// Include context [6] → INTEGER for error code.
	var body []byte
	body = append(body, make([]byte, 10)...) // filler
	// Context tag [6].
	body = append(body, 0xA6, 0x03)
	body = append(body, 0x02, 0x01, byte(code)) // INTEGER
	body = append(body, make([]byte, 5)...) // trailing

	return append([]byte{0x7E, byte(len(body))}, body...)
}

func TestParseASREQ(t *testing.T) {
	p := NewParser()
	client := buildASREQ([]int{18, 17, 23})

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil for AS-REQ")
	}
	if meta.RequestType != "AS" {
		t.Errorf("RequestType = %q, want AS", meta.RequestType)
	}
	if len(meta.ReqCiphers) == 0 {
		t.Error("ReqCiphers is empty")
	} else {
		t.Logf("ReqCiphers: %v", meta.ReqCiphers)
		// Should contain our etypes.
		found := false
		for _, e := range meta.ReqCiphers {
			if e == 18 || e == 17 || e == 23 {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find etype 17, 18, or 23 in ReqCiphers")
		}
	}
}

func TestParseASREP(t *testing.T) {
	p := NewParser()
	server := buildASREP()

	meta := p.Parse(nil, server)
	if meta == nil {
		t.Fatal("Parse returned nil for AS-REP")
	}
	if meta.RequestType != "AS" {
		t.Errorf("RequestType = %q, want AS", meta.RequestType)
	}
	if !meta.Success {
		t.Error("Success should be true for AS-REP")
	}
}

func TestParseTGSREQ(t *testing.T) {
	p := NewParser()
	client := buildTGSREQ()

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil for TGS-REQ")
	}
	if meta.RequestType != "TGS" {
		t.Errorf("RequestType = %q, want TGS", meta.RequestType)
	}
}

func TestParseKRBError(t *testing.T) {
	p := NewParser()
	server := buildKRBError(24) // KDC_ERR_PREAUTH_FAILED

	meta := p.Parse(nil, server)
	if meta == nil {
		t.Fatal("Parse returned nil for KRB-ERROR")
	}
	if meta.Success {
		t.Error("Success should be false for KRB-ERROR")
	}
	if meta.ErrorCode != 24 {
		t.Errorf("ErrorCode = %d, want 24", meta.ErrorCode)
	}
	if meta.ErrorMsg != "KDC_ERR_PREAUTH_FAILED" {
		t.Errorf("ErrorMsg = %q, want KDC_ERR_PREAUTH_FAILED", meta.ErrorMsg)
	}
}

func TestParseRequestResponse(t *testing.T) {
	p := NewParser()
	client := buildASREQ([]int{18, 17})
	server := buildASREP()

	meta := p.Parse(client, server)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.RequestType != "AS" {
		t.Errorf("RequestType = %q, want AS", meta.RequestType)
	}
	if !meta.Success {
		t.Error("Success should be true when REP is present")
	}
}

func TestCanParse(t *testing.T) {
	p := NewParser()

	if !p.CanParse(buildASREQ(nil)) {
		t.Error("CanParse should be true for AS-REQ")
	}
	if !p.CanParse(buildASREP()) {
		t.Error("CanParse should be true for AS-REP")
	}
	if !p.CanParse(buildTGSREQ()) {
		t.Error("CanParse should be true for TGS-REQ")
	}
	if !p.CanParse(buildKRBError(24)) {
		t.Error("CanParse should be true for KRB-ERROR")
	}
	if p.CanParse([]byte("GET / HTTP/1.1")) {
		t.Error("CanParse should be false for HTTP")
	}
	if p.CanParse(nil) {
		t.Error("CanParse should be false for nil")
	}
}

func TestEtypeName(t *testing.T) {
	tests := []struct {
		etype int
		want  string
	}{
		{17, "AES128-CTS-HMAC-SHA1"},
		{18, "AES256-CTS-HMAC-SHA1"},
		{23, "RC4-HMAC"},
		{99, "etype-99"},
	}
	for _, tt := range tests {
		got := EtypeName(tt.etype)
		if got != tt.want {
			t.Errorf("EtypeName(%d) = %q, want %q", tt.etype, got, tt.want)
		}
	}
}

func TestNonKerberosData(t *testing.T) {
	p := NewParser()
	meta := p.Parse([]byte("not kerberos"), nil)
	if meta != nil {
		t.Error("expected nil for non-Kerberos data")
	}
}
