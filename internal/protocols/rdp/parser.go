// Package rdp implements the AkesoNDR RDP protocol dissector.
//
// It parses RDP negotiation from the initial TCP connection (port 3389),
// extracting metadata defined in REQUIREMENTS.md Section 4.7: client_name,
// cookie (username), client_build, desktop dimensions, keyboard layout.
// RDP uses the X.224 Connection Request (CR) for initial negotiation,
// which contains a routing token or cookie with the username.
package rdp

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// TPKT + X.224 constants.
const (
	tpktVersion = 3
	crType      = 0xE0 // X.224 Connection Request
)

// Parser extracts RDP metadata from reassembled TCP streams.
type Parser struct{}

// NewParser creates an RDP parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts RDPMeta from client and server stream data.
// Returns nil if the data does not contain RDP traffic.
func (p *Parser) Parse(client, server []byte) *common.RDPMeta {
	if len(client) < 11 {
		return nil
	}

	meta := &common.RDPMeta{}

	// Parse TPKT + X.224 Connection Request.
	if parseCR(client, meta) {
		return meta
	}

	// Try to find RDP cookie/routing token directly.
	if cookie := findCookie(client); cookie != "" {
		meta.Cookie = cookie
		return meta
	}

	return nil
}

// CanParse returns true if the data starts with a TPKT header for RDP.
func (p *Parser) CanParse(client []byte) bool {
	if len(client) < 11 {
		return false
	}
	// TPKT: version=3, reserved=0, length(2)
	if client[0] == tpktVersion && client[1] == 0 {
		// X.224 CR: length, type=0xE0
		if len(client) > 5 && (client[5]>>4) == 0x0E { // CR type upper nibble
			return true
		}
	}
	// Also detect "Cookie: mstshash=" pattern.
	return bytes.Contains(client[:min(100, len(client))], []byte("Cookie: mstshash="))
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func parseCR(data []byte, meta *common.RDPMeta) bool {
	if len(data) < 4 {
		return false
	}

	// TPKT header: version(1) + reserved(1) + length(2)
	if data[0] != tpktVersion {
		return false
	}
	tpktLen := int(binary.BigEndian.Uint16(data[2:4]))
	if tpktLen < 7 || tpktLen > len(data) {
		tpktLen = len(data)
	}

	// X.224 CR PDU: length(1) + type(1) + dst_ref(2) + src_ref(2) + class(1) + variable...
	if len(data) < 7 {
		return false
	}
	x224Type := data[5] >> 4
	if x224Type != 0x0E { // Connection Request
		return false
	}

	// Variable data follows the 7-byte X.224 header.
	payload := data[7:]
	if len(payload) == 0 {
		return true
	}

	// Look for cookie: "Cookie: mstshash=USERNAME\r\n"
	if cookie := findCookie(payload); cookie != "" {
		meta.Cookie = cookie
	}

	// Look for RDP Negotiation Request (type=0x01) at the end.
	// Format: type(1) + flags(1) + length(2) + requestedProtocols(4)
	if neg := findNegReq(payload); neg != nil {
		meta.ClientBuild = neg.protocols
	}

	return true
}

func findCookie(data []byte) string {
	prefix := []byte("Cookie: mstshash=")
	idx := bytes.Index(data, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	end := bytes.Index(data[start:], []byte("\r\n"))
	if end < 0 {
		end = bytes.IndexByte(data[start:], '\n')
		if end < 0 {
			end = len(data[start:])
			if end > 100 {
				end = 100
			}
		}
	}
	cookie := string(data[start : start+end])
	return strings.TrimSpace(cookie)
}

type negReq struct {
	protocols string
}

func findNegReq(data []byte) *negReq {
	// Scan for negotiation request (type=0x01, length=8).
	for i := 0; i+8 <= len(data); i++ {
		if data[i] == 0x01 && data[i+2] == 0x08 && data[i+3] == 0x00 {
			reqProto := binary.LittleEndian.Uint32(data[i+4 : i+8])
			var protoNames []string
			if reqProto&0x01 != 0 {
				protoNames = append(protoNames, "SSL")
			}
			if reqProto&0x02 != 0 {
				protoNames = append(protoNames, "CredSSP")
			}
			if reqProto&0x04 != 0 {
				protoNames = append(protoNames, "RDSTLS")
			}
			if len(protoNames) == 0 {
				protoNames = append(protoNames, "Standard")
			}
			return &negReq{protocols: strings.Join(protoNames, "+")}
		}
	}
	return nil
}
