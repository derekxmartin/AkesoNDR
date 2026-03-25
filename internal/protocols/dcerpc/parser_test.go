package dcerpc

import (
	"encoding/binary"
	"testing"
)

// buildBindRequest builds a minimal DCE-RPC Bind request with a UUID.
func buildBindRequest(uuid [16]byte) []byte {
	// DCE-RPC header (16 bytes).
	hdr := make([]byte, dceHeaderSize)
	hdr[0] = 5  // version
	hdr[1] = 0  // minor version
	hdr[2] = pktBind
	hdr[3] = 0x03 // flags: first+last frag

	// Bind body: max_xmit(2) + max_recv(2) + assoc_group(4) +
	// num_ctx_items(4, actually 1 byte + 3 padding) + context.
	body := make([]byte, 12)
	binary.LittleEndian.PutUint16(body[0:2], 4096) // max_xmit
	binary.LittleEndian.PutUint16(body[2:4], 4096) // max_recv
	binary.LittleEndian.PutUint32(body[4:8], 0)    // assoc_group
	body[8] = 1  // num context items
	body[9] = 0  // padding
	body[10] = 0
	body[11] = 0

	// Context entry: ctx_id(2) + num_transfer(1) + pad(1) + abstract_syntax(20).
	ctx := make([]byte, 4+20)
	binary.LittleEndian.PutUint16(ctx[0:2], 0) // context_id
	ctx[2] = 1 // num_transfer_syntaxes
	ctx[3] = 0 // padding
	copy(ctx[4:20], uuid[:])
	// version after UUID (4 bytes).
	binary.LittleEndian.PutUint32(ctx[20:24], 1) // version

	pkt := append(hdr, body...)
	pkt = append(pkt, ctx...)

	// Set frag_length.
	binary.LittleEndian.PutUint16(pkt[8:10], uint16(len(pkt)))

	return pkt
}

// buildRPCRequest builds a minimal DCE-RPC Request with an opnum.
func buildRPCRequest(opNum uint16) []byte {
	hdr := make([]byte, dceHeaderSize)
	hdr[0] = 5
	hdr[1] = 0
	hdr[2] = pktRequest
	hdr[3] = 0x03

	// Request body: alloc_hint(4) + context_id(2) + opnum(2).
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], 0)      // alloc_hint
	binary.LittleEndian.PutUint16(body[4:6], 0)      // context_id
	binary.LittleEndian.PutUint16(body[6:8], opNum)

	pkt := append(hdr, body...)
	binary.LittleEndian.PutUint16(pkt[8:10], uint16(len(pkt)))

	return pkt
}

// svcctlUUID is the svcctl (Service Control Manager) UUID.
func svcctlUUID() [16]byte {
	// 367abb81-9844-35f1-ad32-98f038001003
	var uuid [16]byte
	binary.LittleEndian.PutUint32(uuid[0:4], 0x367abb81)
	binary.LittleEndian.PutUint16(uuid[4:6], 0x9844)
	binary.LittleEndian.PutUint16(uuid[6:8], 0x35f1)
	uuid[8] = 0xad
	uuid[9] = 0x32
	uuid[10] = 0x98
	uuid[11] = 0xf0
	uuid[12] = 0x38
	uuid[13] = 0x00
	uuid[14] = 0x10
	uuid[15] = 0x03
	return uuid
}

func TestParseBindRequest(t *testing.T) {
	p := NewParser()
	client := buildBindRequest(svcctlUUID())

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.Endpoint != "svcctl" {
		t.Errorf("Endpoint = %q, want svcctl", meta.Endpoint)
	}
}

func TestParseRPCRequest(t *testing.T) {
	p := NewParser()
	// First bind to establish endpoint context.
	bind := buildBindRequest(svcctlUUID())
	request := buildRPCRequest(12) // CreateServiceW

	// Concatenate bind + request.
	client := append(bind, request...)

	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	if meta.Endpoint != "svcctl" {
		t.Errorf("Endpoint = %q, want svcctl", meta.Endpoint)
	}
	if meta.Operation != "CreateServiceW" {
		t.Errorf("Operation = %q, want CreateServiceW", meta.Operation)
	}
}

func TestParseUnknownUUID(t *testing.T) {
	p := NewParser()
	var unknownUUID [16]byte
	unknownUUID[0] = 0xAA
	unknownUUID[15] = 0xBB

	client := buildBindRequest(unknownUUID)
	meta := p.Parse(client, nil)
	if meta == nil {
		t.Fatal("Parse returned nil")
	}
	// Should return the raw UUID since it's not in the known list.
	if meta.Endpoint == "" {
		t.Error("Endpoint should not be empty")
	}
}

func TestCanParse(t *testing.T) {
	p := NewParser()
	if !p.CanParse(buildBindRequest(svcctlUUID())) {
		t.Error("should be true for DCE-RPC bind")
	}
	if !p.CanParse(buildRPCRequest(0)) {
		t.Error("should be true for DCE-RPC request")
	}
	if p.CanParse([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("should be false for HTTP")
	}
	if p.CanParse(nil) {
		t.Error("should be false for nil")
	}
}

func TestMapOperation(t *testing.T) {
	tests := []struct {
		endpoint string
		opNum    int
		want     string
	}{
		{"svcctl", 7, "OpenSCManager"},
		{"svcctl", 12, "CreateServiceW"},
		{"samr", 13, "EnumerateUsersInDomain"},
		{"atsvc", 0, "NetrJobAdd"},
		{"unknown", 99, "op_99"},
	}
	for _, tt := range tests {
		got := mapOperation(tt.endpoint, tt.opNum)
		if got != tt.want {
			t.Errorf("mapOperation(%q, %d) = %q, want %q", tt.endpoint, tt.opNum, got, tt.want)
		}
	}
}

func TestNonDCERPCData(t *testing.T) {
	p := NewParser()
	meta := p.Parse([]byte("not dcerpc"), nil)
	if meta != nil {
		t.Error("expected nil for non-DCE-RPC data")
	}
}
