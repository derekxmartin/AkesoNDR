// Package ntlm implements the AkesoNDR NTLM protocol dissector.
//
// It parses NTLM authentication messages (Type 1/2/3) that can appear
// within SMB, HTTP, LDAP, and other protocols. Extracts domain, hostname,
// username, and success status — metadata defined in REQUIREMENTS.md
// Section 4.7. This feeds the NTLM & Credential Abuse detector (Section 5.6):
// NTLM relay detection, pass-the-hash indicators, cleartext credential exposure.
package ntlm

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// NTLM signature and message types.
var ntlmSignature = []byte("NTLMSSP\x00")

const (
	ntlmNegotiate    = 1 // Type 1: Negotiate
	ntlmChallenge    = 2 // Type 2: Challenge
	ntlmAuthenticate = 3 // Type 3: Authenticate
)

// Parser extracts NTLM metadata from stream data.
type Parser struct{}

// NewParser creates an NTLM parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts NTLMMeta from client and server data.
// Searches both directions for NTLM messages (they can appear in either).
// Returns nil if no NTLM messages are found.
func (p *Parser) Parse(client, server []byte) *common.NTLMMeta {
	meta := &common.NTLMMeta{}
	found := false

	// Search for NTLM messages in both directions.
	for _, data := range [][]byte{client, server} {
		msgs := findNTLMMessages(data)
		for _, msg := range msgs {
			if parseNTLMMessage(msg, meta) {
				found = true
			}
		}
	}

	if !found {
		return nil
	}
	return meta
}

// CanParse returns true if the data contains an NTLM signature.
func (p *Parser) CanParse(data []byte) bool {
	return bytes.Contains(data, ntlmSignature)
}

// FindInStream searches for NTLM authentication in any protocol stream
// data and returns metadata if found. Useful for detecting NTLM within
// HTTP, SMB, LDAP, etc.
func FindInStream(data []byte) *common.NTLMMeta {
	p := NewParser()
	return p.Parse(data, nil)
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func findNTLMMessages(data []byte) [][]byte {
	var msgs [][]byte
	search := data
	for {
		idx := bytes.Index(search, ntlmSignature)
		if idx < 0 {
			break
		}
		msgStart := search[idx:]
		// Ensure we have at least the header (signature + type).
		if len(msgStart) >= 12 {
			msgs = append(msgs, msgStart)
		}
		search = search[idx+len(ntlmSignature):]
	}
	return msgs
}

func parseNTLMMessage(data []byte, meta *common.NTLMMeta) bool {
	if len(data) < 12 {
		return false
	}
	if !bytes.HasPrefix(data, ntlmSignature) {
		return false
	}

	msgType := binary.LittleEndian.Uint32(data[8:12])

	switch msgType {
	case ntlmNegotiate:
		return parseNegotiate(data, meta)
	case ntlmChallenge:
		return parseChallenge(data, meta)
	case ntlmAuthenticate:
		return parseAuthenticate(data, meta)
	}
	return false
}

// Type 1: Negotiate — contains domain and hostname hints.
func parseNegotiate(data []byte, meta *common.NTLMMeta) bool {
	if len(data) < 32 {
		return false
	}
	// Flags at offset 12 (4 bytes).
	// Domain name: security buffer at offset 16 (len:2, maxlen:2, offset:4)
	// Workstation: security buffer at offset 24 (len:2, maxlen:2, offset:4)

	if domain := readSecurityBuffer(data, 16); domain != "" {
		meta.Domain = domain
	}
	if hostname := readSecurityBuffer(data, 24); hostname != "" {
		meta.Hostname = hostname
	}
	return true
}

// Type 2: Challenge — contains target name and info.
func parseChallenge(data []byte, meta *common.NTLMMeta) bool {
	if len(data) < 32 {
		return false
	}
	// Target name: security buffer at offset 12 (len:2, maxlen:2, offset:4)
	if target := readSecurityBufferUnicode(data, 12); target != "" {
		if meta.Domain == "" {
			meta.Domain = target
		}
	}
	return true
}

// Type 3: Authenticate — contains domain, username, hostname.
func parseAuthenticate(data []byte, meta *common.NTLMMeta) bool {
	if len(data) < 88 {
		return false
	}
	// Security buffers:
	// LmChallengeResponse: offset 12
	// NtChallengeResponse: offset 20
	// DomainName: offset 28
	// UserName: offset 36
	// Workstation: offset 44

	if domain := readSecurityBufferUnicode(data, 28); domain != "" {
		meta.Domain = domain
	}
	if username := readSecurityBufferUnicode(data, 36); username != "" {
		meta.Username = username
	}
	if hostname := readSecurityBufferUnicode(data, 44); hostname != "" {
		meta.Hostname = hostname
	}

	// If we have a username in Type 3, consider auth attempted (success
	// depends on server response which we may not see in this direction).
	if meta.Username != "" {
		meta.Success = true // Assume success unless error detected
		meta.Status = "authenticate"
	}

	return true
}

// readSecurityBuffer reads an ASCII security buffer field.
func readSecurityBuffer(data []byte, offset int) string {
	if offset+8 > len(data) {
		return ""
	}
	bufLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	bufOff := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))

	if bufLen <= 0 || bufOff < 0 || bufOff+bufLen > len(data) {
		return ""
	}

	s := string(data[bufOff : bufOff+bufLen])
	return strings.TrimRight(s, "\x00")
}

// readSecurityBufferUnicode reads a UTF-16LE security buffer field.
func readSecurityBufferUnicode(data []byte, offset int) string {
	if offset+8 > len(data) {
		return ""
	}
	bufLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	bufOff := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))

	if bufLen <= 0 || bufOff < 0 || bufOff+bufLen > len(data) {
		return ""
	}

	raw := data[bufOff : bufOff+bufLen]
	return decodeUTF16LE(raw)
}

func decodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	u16s := make([]uint16, len(data)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}
	runes := utf16.Decode(u16s)
	return strings.TrimRight(string(runes), "\x00")
}
