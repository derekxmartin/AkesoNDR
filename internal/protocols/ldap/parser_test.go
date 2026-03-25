package ldap

import (
	"testing"
)

// buildBindRequest builds a minimal LDAP simple bind request.
func buildBindRequest(dn string) []byte {
	// OCTET STRING for DN.
	dnBytes := []byte(dn)
	dnField := append([]byte{0x04, byte(len(dnBytes))}, dnBytes...)

	// Simple auth (tag 0x80) with password "password".
	password := []byte("password")
	authField := append([]byte{0x80, byte(len(password))}, password...)

	// Version INTEGER (3).
	versionField := []byte{0x02, 0x01, 0x03}

	// BindRequest APPLICATION 0 (tag 0x60).
	body := append(versionField, dnField...)
	body = append(body, authField...)
	bindReq := append([]byte{0x60, byte(len(body))}, body...)

	// Message ID.
	msgID := []byte{0x02, 0x01, 0x01}

	// SEQUENCE wrapper.
	inner := append(msgID, bindReq...)
	return append([]byte{0x30, byte(len(inner))}, inner...)
}

// buildSearchRequest builds a minimal LDAP search request.
func buildSearchRequest(baseDN string, scope int) []byte {
	// Base DN.
	dnBytes := []byte(baseDN)
	dnField := append([]byte{0x04, byte(len(dnBytes))}, dnBytes...)

	// Scope (ENUMERATED).
	scopeField := []byte{0x0A, 0x01, byte(scope)}

	// SearchRequest APPLICATION 3 (tag 0x63).
	body := append(dnField, scopeField...)
	searchReq := append([]byte{0x63, byte(len(body))}, body...)

	// Message ID.
	msgID := []byte{0x02, 0x01, 0x02}

	// SEQUENCE wrapper.
	inner := append(msgID, searchReq...)
	return append([]byte{0x30, byte(len(inner))}, inner...)
}

// buildBindResponse builds a minimal LDAP bind response with a result code.
func buildBindResponse(resultCode int) []byte {
	// BindResponse APPLICATION 1 (tag 0x61).
	// Body: result code (ENUMERATED) + matched DN + error message.
	resultField := []byte{0x0A, 0x01, byte(resultCode)}
	matchedDN := []byte{0x04, 0x00}       // empty
	errorMsg := []byte{0x04, 0x00}         // empty

	body := append(resultField, matchedDN...)
	body = append(body, errorMsg...)
	bindResp := append([]byte{0x61, byte(len(body))}, body...)

	msgID := []byte{0x02, 0x01, 0x01}
	inner := append(msgID, bindResp...)
	return append([]byte{0x30, byte(len(inner))}, inner...)
}

func TestParseBindRequest(t *testing.T) {
	p := NewParser()
	client := buildBindRequest("cn=admin,dc=example,dc=com")

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.BaseObject != "cn=admin,dc=example,dc=com" {
		t.Errorf("BaseObject = %q", meta.BaseObject)
	}
	if meta.Query != "simple_bind_cleartext" {
		t.Errorf("Query = %q, want simple_bind_cleartext", meta.Query)
	}
}

func TestParseSearchRequest(t *testing.T) {
	p := NewParser()
	client := buildSearchRequest("dc=corp,dc=local", scopeSubtree)

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.BaseObject != "dc=corp,dc=local" {
		t.Errorf("BaseObject = %q", meta.BaseObject)
	}
	if meta.QueryScope != "sub" {
		t.Errorf("QueryScope = %q, want sub", meta.QueryScope)
	}
}

func TestParseBindResponse(t *testing.T) {
	p := NewParser()
	server := buildBindResponse(49) // invalidCredentials

	meta := p.Parse(nil, server)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.ResultCode != 49 {
		t.Errorf("ResultCode = %d, want 49", meta.ResultCode)
	}
	if meta.BindErrorCount != 1 {
		t.Errorf("BindErrorCount = %d, want 1", meta.BindErrorCount)
	}
}

func TestParseBindSuccessResponse(t *testing.T) {
	p := NewParser()
	server := buildBindResponse(0) // success

	meta := p.Parse(nil, server)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.ResultCode != 0 {
		t.Errorf("ResultCode = %d, want 0", meta.ResultCode)
	}
	if meta.BindErrorCount != 0 {
		t.Errorf("BindErrorCount = %d, want 0", meta.BindErrorCount)
	}
}

func TestCanParse(t *testing.T) {
	p := NewParser()
	if !p.CanParse(buildBindRequest("cn=test")) {
		t.Error("should be true for LDAP bind request")
	}
	if !p.CanParse(buildSearchRequest("dc=test", 0)) {
		t.Error("should be true for LDAP search request")
	}
	if p.CanParse([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("should be false for HTTP")
	}
	if p.CanParse(nil) {
		t.Error("should be false for nil")
	}
}

func TestResultCodeName(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{0, "success"},
		{49, "invalidCredentials"},
		{50, "insufficientAccessRights"},
		{999, "code_999"},
	}
	for _, tt := range tests {
		got := ResultCodeName(tt.code)
		if got != tt.want {
			t.Errorf("ResultCodeName(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestNonLDAPData(t *testing.T) {
	p := NewParser()
	meta := p.Parse([]byte("not ldap"), nil)
	if meta != nil {
		t.Error("expected nil for non-LDAP data")
	}
}
