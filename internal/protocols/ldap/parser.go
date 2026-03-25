// Package ldap implements the AkesoNDR LDAP protocol dissector.
//
// It parses LDAP bind, search, and result messages from reassembled TCP
// streams (port 389/636), extracting metadata defined in REQUIREMENTS.md
// Section 4.7: base_object, query, query_scope, result_code, bind error
// count, and encrypted SASL payload count. Critically, it detects cleartext
// LDAP simple binds — a credential exposure risk flagged by Section 5.6.
//
// LDAP uses ASN.1 BER encoding. This parser does minimal BER parsing
// sufficient for metadata extraction.
package ldap

import (
	"encoding/binary"
	"fmt"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// LDAP protocol operation codes (application tags).
const (
	opBindRequest     = 0  // [APPLICATION 0]
	opBindResponse    = 1  // [APPLICATION 1]
	opSearchRequest   = 3  // [APPLICATION 3]
	opSearchResultEntry = 4  // [APPLICATION 4]
	opSearchResultDone  = 5  // [APPLICATION 5]
)

// LDAP search scope values.
const (
	scopeBase    = 0
	scopeOneLevel = 1
	scopeSubtree = 2
)

// Parser extracts LDAP metadata from reassembled TCP streams.
type Parser struct{}

// NewParser creates an LDAP parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts LDAPMeta from client and server stream data.
// Returns nil if the data does not contain LDAP traffic.
func (p *Parser) Parse(client, server []byte) *common.LDAPMeta {
	meta := &common.LDAPMeta{}
	found := false

	// Parse client messages (bind requests, search requests).
	if len(client) > 0 {
		if parseLDAPMessages(client, meta, true) {
			found = true
		}
	}

	// Parse server messages (bind responses, search results).
	if len(server) > 0 {
		if parseLDAPMessages(server, meta, false) {
			found = true
		}
	}

	if !found {
		return nil
	}
	return meta
}

// CanParse returns true if the data starts with an ASN.1 SEQUENCE tag
// followed by an LDAP message structure.
func (p *Parser) CanParse(data []byte) bool {
	if len(data) < 7 {
		return false
	}
	// LDAP messages are wrapped in SEQUENCE (0x30).
	if data[0] != 0x30 {
		return false
	}
	// Inside: INTEGER (message ID) + APPLICATION tag for operation.
	// Skip the SEQUENCE length, find the INTEGER (0x02) for message ID.
	off := skipLength(data, 1)
	if off < 0 || off+3 >= len(data) {
		return false
	}
	if data[off] != 0x02 { // INTEGER tag
		return false
	}
	// Skip message ID, check for APPLICATION tag.
	idLen := int(data[off+1])
	appOff := off + 2 + idLen
	if appOff >= len(data) {
		return false
	}
	// APPLICATION tags: 0x60 (BindRequest), 0x61 (BindResponse),
	// 0x63 (SearchRequest), 0x64 (SearchResultEntry), 0x65 (SearchResultDone)
	appTag := data[appOff]
	return (appTag >= 0x60 && appTag <= 0x67) || appTag == 0x42 || appTag == 0x43
}

// ---------------------------------------------------------------------------
// Internal message parsing
// ---------------------------------------------------------------------------

func parseLDAPMessages(data []byte, meta *common.LDAPMeta, isClient bool) bool {
	found := false
	off := 0

	for off < len(data) {
		if data[off] != 0x30 { // SEQUENCE
			break
		}

		// Read SEQUENCE length.
		seqLen, lenSize := readBERLength(data[off+1:])
		if seqLen <= 0 || lenSize <= 0 {
			break
		}
		msgStart := off + 1 + lenSize
		msgEnd := msgStart + seqLen
		if msgEnd > len(data) {
			msgEnd = len(data)
		}

		msg := data[msgStart:msgEnd]
		if parseSingleMessage(msg, meta, isClient) {
			found = true
		}

		off = msgEnd
	}
	return found
}

func parseSingleMessage(msg []byte, meta *common.LDAPMeta, isClient bool) bool {
	if len(msg) < 3 {
		return false
	}

	// Skip message ID (INTEGER).
	if msg[0] != 0x02 {
		return false
	}
	idLen := int(msg[1])
	off := 2 + idLen
	if off >= len(msg) {
		return false
	}

	// APPLICATION tag determines operation.
	appTag := msg[off]
	opCode := int(appTag & 0x1F)

	switch opCode {
	case opBindRequest:
		return parseBindRequest(msg[off:], meta)
	case opBindResponse:
		return parseBindResponse(msg[off:], meta)
	case opSearchRequest:
		return parseSearchRequest(msg[off:], meta)
	case opSearchResultDone:
		return parseSearchResultDone(msg[off:], meta)
	}
	return false
}

// parseBindRequest extracts bind info. A simple bind (auth choice = 0x80)
// over cleartext LDAP is a credential exposure risk.
func parseBindRequest(data []byte, meta *common.LDAPMeta) bool {
	if len(data) < 3 {
		return false
	}

	// Skip APPLICATION tag + length.
	off := 1
	bodyLen, lenSize := readBERLength(data[off:])
	if bodyLen <= 0 {
		return false
	}
	off += lenSize

	// Bind request body: version(INTEGER) + name(OCTET STRING) + auth(CHOICE)
	// Version.
	if off >= len(data) || data[off] != 0x02 {
		return true
	}
	verLen := int(data[off+1])
	off += 2 + verLen

	// Name (DN being bound).
	if off >= len(data) || data[off] != 0x04 {
		return true
	}
	nameLen := int(data[off+1])
	if off+2+nameLen <= len(data) {
		name := string(data[off+2 : off+2+nameLen])
		if meta.BaseObject == "" {
			meta.BaseObject = name
		}
	}
	off += 2 + nameLen

	// Auth choice: 0x80 = simple bind (password in cleartext!), 0xA3 = SASL.
	if off < len(data) {
		authTag := data[off]
		if authTag == 0x80 {
			meta.Query = "simple_bind_cleartext"
		} else if authTag == 0xA3 {
			meta.Query = "sasl_bind"
			meta.SASLPayloads++
		}
	}

	return true
}

func parseBindResponse(data []byte, meta *common.LDAPMeta) bool {
	if len(data) < 3 {
		return false
	}

	// Extract result code from bind response.
	code := findResultCode(data)
	if code >= 0 {
		meta.ResultCode = code
		if code != 0 { // 0 = success
			meta.BindErrorCount++
		}
	}
	return true
}

func parseSearchRequest(data []byte, meta *common.LDAPMeta) bool {
	if len(data) < 5 {
		return false
	}

	// Skip APPLICATION tag + length.
	off := 1
	_, lenSize := readBERLength(data[off:])
	off += lenSize

	// Search request: baseObject(OCTET STRING) + scope(ENUM) + ...
	if off >= len(data) || data[off] != 0x04 {
		return true
	}
	baseLen := int(data[off+1])
	if off+2+baseLen <= len(data) {
		meta.BaseObject = string(data[off+2 : off+2+baseLen])
	}
	off += 2 + baseLen

	// Scope (ENUMERATED, tag 0x0A).
	if off+2 < len(data) && data[off] == 0x0A {
		scopeLen := int(data[off+1])
		if scopeLen == 1 && off+2 < len(data) {
			meta.QueryScope = scopeName(int(data[off+2]))
		}
		off += 2 + scopeLen
	}

	return true
}

func parseSearchResultDone(data []byte, meta *common.LDAPMeta) bool {
	code := findResultCode(data)
	if code >= 0 {
		meta.ResultCode = code
	}
	return true
}

// ---------------------------------------------------------------------------
// BER helpers
// ---------------------------------------------------------------------------

func findResultCode(data []byte) int {
	// Result code is the first ENUMERATED (0x0A) in the message body.
	for i := 0; i+2 < len(data); i++ {
		if data[i] == 0x0A && data[i+1] == 0x01 && i+2 < len(data) {
			return int(data[i+2])
		}
	}
	return -1
}

func readBERLength(data []byte) (length int, size int) {
	if len(data) == 0 {
		return -1, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || numBytes > 4 || numBytes >= len(data) {
		return -1, 0
	}
	length = 0
	for i := 1; i <= numBytes; i++ {
		length = length<<8 | int(data[i])
	}
	return length, 1 + numBytes
}

func skipLength(data []byte, off int) int {
	if off >= len(data) {
		return -1
	}
	if data[off] < 0x80 {
		return off + 1
	}
	numBytes := int(data[off] & 0x7F)
	return off + 1 + numBytes
}

func scopeName(s int) string {
	switch s {
	case scopeBase:
		return "base"
	case scopeOneLevel:
		return "one"
	case scopeSubtree:
		return "sub"
	default:
		return fmt.Sprintf("scope_%d", s)
	}
}

// ResultCodeName returns a human-readable LDAP result code name.
func ResultCodeName(code int) string {
	names := map[int]string{
		0:  "success",
		1:  "operationsError",
		2:  "protocolError",
		7:  "authMethodNotSupported",
		14: "saslBindInProgress",
		32: "noSuchObject",
		48: "inappropriateAuthentication",
		49: "invalidCredentials",
		50: "insufficientAccessRights",
	}
	if name, ok := names[code]; ok {
		return name
	}
	return fmt.Sprintf("code_%d", code)
}

// PortNumber constants for LDAP.
func PortNumber() uint16 { return 389 }

// Placeholder for compatibility — replaced by actual parser above.
var _ = binary.BigEndian
