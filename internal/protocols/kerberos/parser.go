// Package kerberos implements the AkesoNDR Kerberos protocol dissector.
//
// It parses Kerberos AS-REQ, AS-REP, TGS-REQ, TGS-REP, and KRB-ERROR
// messages from raw TCP/UDP stream data (port 88), extracting metadata
// defined in REQUIREMENTS.md Section 4.5: request type, client/service
// principals, encryption types, success/error status. This metadata feeds
// the Kerberos attack detector (Section 5.5) — high-volume TGS-REQ with
// RC4 (etype 23) indicates Kerberoasting.
//
// Kerberos uses ASN.1 DER encoding. This parser does minimal ASN.1 parsing
// sufficient for metadata extraction without a full ASN.1 library.
package kerberos

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// Kerberos message type tags (application tags).
const (
	tagASREQ    = 10 // [APPLICATION 10]
	tagASREP    = 11 // [APPLICATION 11]
	tagTGSREQ   = 12 // [APPLICATION 12]
	tagTGSREP   = 13 // [APPLICATION 13]
	tagKRBError = 30 // [APPLICATION 30]
)

// Parser extracts Kerberos metadata from network data.
type Parser struct{}

// NewParser creates a Kerberos parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts KerberosMeta from client and/or server data.
// Returns nil if the data does not contain Kerberos traffic.
func (p *Parser) Parse(client, server []byte) *common.KerberosMeta {
	// Try request first (client), then response (server).
	meta := &common.KerberosMeta{}
	parsed := false

	if len(client) > 0 {
		if parseKerberosMessage(client, meta) {
			parsed = true
		}
	}

	if len(server) > 0 {
		// Parse response — may upgrade metadata (add reply cipher, error, etc.)
		respMeta := &common.KerberosMeta{}
		if parseKerberosMessage(server, respMeta) {
			parsed = true
			// Merge response info into meta.
			if respMeta.Success {
				meta.Success = true
			}
			if respMeta.RepCipher != 0 {
				meta.RepCipher = respMeta.RepCipher
			}
			if respMeta.ErrorCode != 0 {
				meta.ErrorCode = respMeta.ErrorCode
				meta.ErrorMsg = respMeta.ErrorMsg
				meta.Success = false
			}
			if meta.RequestType == "" {
				meta.RequestType = respMeta.RequestType
			}
			if meta.Client == "" {
				meta.Client = respMeta.Client
			}
			if meta.Service == "" {
				meta.Service = respMeta.Service
			}
		}
	}

	if !parsed {
		return nil
	}
	return meta
}

// CanParse returns true if the data looks like a Kerberos message.
func (p *Parser) CanParse(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	// Kerberos messages start with ASN.1 APPLICATION tag.
	tag := getAppTag(data)
	return tag == tagASREQ || tag == tagASREP || tag == tagTGSREQ ||
		tag == tagTGSREP || tag == tagKRBError
}

// ParsePacketData parses Kerberos from raw packet payload (after transport).
func (p *Parser) ParsePacketData(data []byte) *common.KerberosMeta {
	meta := &common.KerberosMeta{}
	if parseKerberosMessage(data, meta) {
		return meta
	}
	return nil
}

// ---------------------------------------------------------------------------
// ASN.1 minimal parser
// ---------------------------------------------------------------------------

func parseKerberosMessage(data []byte, meta *common.KerberosMeta) bool {
	// Skip TCP length prefix if present (4 bytes for Kerberos over TCP).
	if len(data) > 4 {
		possibleLen := int(binary.BigEndian.Uint32(data[:4]))
		if possibleLen == len(data)-4 {
			data = data[4:]
		}
	}

	if len(data) < 2 {
		return false
	}

	tag := getAppTag(data)
	switch tag {
	case tagASREQ:
		meta.RequestType = "AS"
		parseKDCREQ(data, meta)
		return true
	case tagASREP:
		meta.RequestType = "AS"
		meta.Success = true
		parseKDCREP(data, meta)
		return true
	case tagTGSREQ:
		meta.RequestType = "TGS"
		parseKDCREQ(data, meta)
		return true
	case tagTGSREP:
		meta.RequestType = "TGS"
		meta.Success = true
		parseKDCREP(data, meta)
		return true
	case tagKRBError:
		parseKRBError(data, meta)
		return true
	}
	return false
}

// getAppTag extracts the APPLICATION tag number from ASN.1 data.
func getAppTag(data []byte) int {
	if len(data) < 1 {
		return -1
	}
	b := data[0]
	// APPLICATION class = 0x60 | tag number (for tags 0-30)
	if b&0xC0 == 0x40 { // context class — some encodings
		return int(b & 0x1F)
	}
	if b&0xE0 == 0x60 { // APPLICATION + constructed
		return int(b & 0x1F)
	}
	return -1
}

// parseKDCREQ extracts fields from AS-REQ or TGS-REQ.
func parseKDCREQ(data []byte, meta *common.KerberosMeta) {
	// Search for encryption type list (etype) — context tag [8] in KDC-REQ-BODY.
	// Encryption types are SEQUENCE OF INTEGER.
	etypes := findEtypes(data)
	if len(etypes) > 0 {
		meta.ReqCiphers = etypes
	}

	// Extract client principal (cname) — context tag [1] in KDC-REQ-BODY.
	if name := findPrincipalName(data, 0xA1); name != "" {
		meta.Client = name
	}

	// Extract service principal (sname) — context tag [2] in KDC-REQ-BODY.
	if name := findPrincipalName(data, 0xA2); name != "" {
		meta.Service = name
	}

	// Extract realm — context tag [2] in KDC-REQ → GeneralString.
	if realm := findRealm(data); realm != "" {
		if meta.Client != "" && !strings.Contains(meta.Client, "@") {
			meta.Client = meta.Client + "@" + realm
		}
	}
}

// parseKDCREP extracts fields from AS-REP or TGS-REP.
func parseKDCREP(data []byte, meta *common.KerberosMeta) {
	// Extract client name.
	if name := findPrincipalName(data, 0xA1); name != "" {
		meta.Client = name
	}

	// Look for enc-part etype — the reply cipher.
	etypes := findEtypes(data)
	if len(etypes) > 0 {
		meta.RepCipher = etypes[0]
	}
}

// parseKRBError extracts error info from KRB-ERROR message.
func parseKRBError(data []byte, meta *common.KerberosMeta) {
	meta.Success = false

	// Error code is in context tag [6] as INTEGER.
	code := findErrorCode(data)
	meta.ErrorCode = code
	meta.ErrorMsg = kerberosErrorName(code)

	// Try to determine if this was AS or TGS from context.
	if name := findPrincipalName(data, 0xA1); name != "" {
		meta.Client = name
	}
	if name := findPrincipalName(data, 0xA2); name != "" {
		meta.Service = name
	}
}

// ---------------------------------------------------------------------------
// ASN.1 field finders (byte-pattern search — sufficient for POC metadata)
// ---------------------------------------------------------------------------

// findEtypes searches for a sequence of integers that look like Kerberos
// encryption types. Common etypes: 17 (AES128), 18 (AES256), 23 (RC4).
func findEtypes(data []byte) []int {
	var etypes []int
	for i := 0; i+3 < len(data); i++ {
		// Look for SEQUENCE tag (0x30) followed by integers (0x02).
		if data[i] == 0x30 && i+2 < len(data) {
			seqLen := int(data[i+1])
			if seqLen > 0 && seqLen < 100 && i+2+seqLen <= len(data) {
				// Try to parse as sequence of integers.
				seq := data[i+2 : i+2+seqLen]
				ets := parseIntSequence(seq)
				if len(ets) > 0 && looksLikeEtypes(ets) {
					etypes = ets
					break
				}
			}
		}
	}
	return etypes
}

func parseIntSequence(data []byte) []int {
	var vals []int
	off := 0
	for off+2 < len(data) {
		if data[off] != 0x02 { // INTEGER tag
			break
		}
		intLen := int(data[off+1])
		if intLen <= 0 || off+2+intLen > len(data) {
			break
		}
		val := 0
		for j := 0; j < intLen; j++ {
			val = val<<8 | int(data[off+2+j])
		}
		vals = append(vals, val)
		off += 2 + intLen
	}
	return vals
}

func looksLikeEtypes(vals []int) bool {
	// Kerberos etypes are small positive integers, typically 1-24.
	for _, v := range vals {
		if v >= 1 && v <= 24 {
			return true
		}
	}
	return false
}

// findPrincipalName searches for a KerberosString in the data following
// a context tag. Returns the name or empty string.
func findPrincipalName(data []byte, contextTag byte) string {
	for i := 0; i+4 < len(data); i++ {
		if data[i] == contextTag {
			// Look for GeneralString (0x1B) or UTF8String (0x0C) nearby.
			for j := i + 1; j+2 < len(data) && j < i+30; j++ {
				if data[j] == 0x1B || data[j] == 0x0C || data[j] == 0x16 {
					strLen := int(data[j+1])
					if strLen > 0 && strLen < 200 && j+2+strLen <= len(data) {
						s := string(data[j+2 : j+2+strLen])
						if isPrintableString(s) {
							return s
						}
					}
				}
			}
		}
	}
	return ""
}

func findRealm(data []byte) string {
	// Realm is a GeneralString, often preceded by context tag [2] in KDC-REQ.
	for i := 0; i+4 < len(data); i++ {
		if data[i] == 0xA2 {
			for j := i + 1; j+2 < len(data) && j < i+20; j++ {
				if data[j] == 0x1B || data[j] == 0x0C || data[j] == 0x16 {
					strLen := int(data[j+1])
					if strLen > 0 && strLen < 100 && j+2+strLen <= len(data) {
						s := string(data[j+2 : j+2+strLen])
						if isPrintableString(s) && strings.Contains(s, ".") {
							return s
						}
					}
				}
			}
		}
	}
	return ""
}

func findErrorCode(data []byte) int {
	// Error code is context [6] → INTEGER in KRB-ERROR.
	for i := 0; i+4 < len(data); i++ {
		if data[i] == 0xA6 {
			for j := i + 1; j+2 < len(data) && j < i+10; j++ {
				if data[j] == 0x02 {
					intLen := int(data[j+1])
					if intLen > 0 && intLen <= 4 && j+2+intLen <= len(data) {
						val := 0
						for k := 0; k < intLen; k++ {
							val = val<<8 | int(data[j+2+k])
						}
						return val
					}
				}
			}
		}
	}
	return 0
}

func isPrintableString(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return len(s) > 0
}

// ---------------------------------------------------------------------------
// Error code names
// ---------------------------------------------------------------------------

func kerberosErrorName(code int) string {
	names := map[int]string{
		6:  "KDC_ERR_C_PRINCIPAL_UNKNOWN",
		7:  "KDC_ERR_S_PRINCIPAL_UNKNOWN",
		12: "KDC_ERR_POLICY",
		14: "KDC_ERR_ETYPE_NOSUPP",
		18: "KDC_ERR_CLIENT_REVOKED",
		24: "KDC_ERR_PREAUTH_FAILED",
		25: "KDC_ERR_PREAUTH_REQUIRED",
		31: "KRB_AP_ERR_SKEW",
		41: "KRB_AP_ERR_REPEAT",
		68: "KDC_ERR_WRONG_REALM",
	}
	if name, ok := names[code]; ok {
		return name
	}
	return fmt.Sprintf("KRB_ERR_%d", code)
}

// EtypeName returns a human-readable name for a Kerberos encryption type.
func EtypeName(etype int) string {
	names := map[int]string{
		1:  "DES-CBC-CRC",
		3:  "DES-CBC-MD5",
		17: "AES128-CTS-HMAC-SHA1",
		18: "AES256-CTS-HMAC-SHA1",
		23: "RC4-HMAC",
		24: "RC4-HMAC-EXP",
	}
	if name, ok := names[etype]; ok {
		return name
	}
	return fmt.Sprintf("etype-%d", etype)
}
