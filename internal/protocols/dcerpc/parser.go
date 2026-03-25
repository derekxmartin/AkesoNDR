// Package dcerpc implements the AkesoNDR DCE-RPC protocol dissector.
//
// It parses DCE-RPC bind and request messages from reassembled TCP streams
// (typically over SMB named pipes on port 445 or direct TCP on port 135),
// extracting metadata defined in REQUIREMENTS.md Section 4.7: endpoint UUID,
// operation number, domain, hostname, username. Critical endpoints for
// detection: svcctl (service creation → PsExec), IWbemLoginClientID (WMI
// remote exec), atsvc (scheduled tasks), samr (user enumeration).
package dcerpc

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// DCE-RPC packet types.
const (
	pktBind     = 11
	pktBindAck  = 12
	pktRequest  = 0
	pktResponse = 2
)

// Well-known DCE-RPC endpoint UUIDs.
var knownEndpoints = map[string]string{
	"367abb81-9844-35f1-ad32-98f038001003": "svcctl",        // Service Control Manager
	"338cd001-2244-31f1-aaaa-900038001003": "winreg",        // Remote Registry
	"12345778-1234-abcd-ef00-0123456789ab": "samr",          // SAM Remote Protocol
	"e1af8308-5d1f-11c9-91a4-08002b14a0fa": "epmap",        // Endpoint Mapper
	"d95afe70-a6d5-4259-822e-2c84da1ddb0d": "IWbemLoginClientID", // WMI
	"86d35949-83c9-4044-b424-db363231fd0c": "ITaskSchedulerService", // Task Scheduler
	"378e52b0-c0a9-11cf-822d-00aa0051e40f": "atsvc",        // AT Scheduler (legacy)
	"4b324fc8-1670-01d3-1278-5a47bf6ee188": "srvsvc",       // Server Service
	"12345678-1234-abcd-ef00-01234567cffb": "netlogon",     // Netlogon
	"3919286a-b10c-11d0-9ba8-00c04fd92ef5": "dssetup",      // DS Setup
}

// Parser extracts DCE-RPC metadata from reassembled TCP streams.
type Parser struct{}

// NewParser creates a DCE-RPC parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts DCERPCMeta from client and server stream data.
// Returns nil if the data does not contain DCE-RPC traffic.
func (p *Parser) Parse(client, server []byte) *common.DCERPCMeta {
	meta := &common.DCERPCMeta{}
	found := false

	// Parse client messages (bind requests, RPC requests).
	if parseDCERPCMessages(client, meta) {
		found = true
	}

	// Parse server messages (bind acks, RPC responses).
	if parseDCERPCMessages(server, meta) {
		found = true
	}

	if !found {
		return nil
	}
	return meta
}

// CanParse returns true if the data starts with a DCE-RPC header.
func (p *Parser) CanParse(data []byte) bool {
	return hasDCERPCHeader(data)
}

// ---------------------------------------------------------------------------
// DCE-RPC parsing
// ---------------------------------------------------------------------------

// DCE-RPC header is at least 16 bytes:
// version(1) + version_minor(1) + packet_type(1) + flags(1) +
// data_repr(4) + frag_length(2) + auth_length(2) + call_id(4)
const dceHeaderSize = 16

func hasDCERPCHeader(data []byte) bool {
	if len(data) < dceHeaderSize {
		return false
	}
	// Version 5, minor 0.
	return data[0] == 5 && data[1] == 0
}

func parseDCERPCMessages(data []byte, meta *common.DCERPCMeta) bool {
	found := false
	off := 0

	for off+dceHeaderSize <= len(data) {
		if data[off] != 5 || data[off+1] != 0 {
			// Try to find next header.
			idx := findDCEHeader(data[off+1:])
			if idx < 0 {
				break
			}
			off += 1 + idx
			continue
		}

		pktType := data[off+2]
		fragLen := int(binary.LittleEndian.Uint16(data[off+8 : off+10]))
		if fragLen < dceHeaderSize || off+fragLen > len(data) {
			fragLen = len(data) - off
		}

		pkt := data[off : off+fragLen]

		switch pktType {
		case pktBind:
			if parseBind(pkt, meta) {
				found = true
			}
		case pktRequest:
			if parseRequest(pkt, meta) {
				found = true
			}
		case pktBindAck:
			found = true // Bind acknowledged — connection established.
		case pktResponse:
			found = true
		}

		off += fragLen
	}
	return found
}

// parseBind extracts the interface UUID from a Bind request.
// After the 16-byte header: max_xmit_frag(2) + max_recv_frag(2) +
// assoc_group(4) + num_contexts(1) + padding(3) + context(variable).
// Context: context_id(2) + num_transfer_syntaxes(1) + padding(1) +
// abstract_syntax(20 = UUID:16 + version:4) + ...
func parseBind(pkt []byte, meta *common.DCERPCMeta) bool {
	if len(pkt) < dceHeaderSize+28 {
		return false
	}

	// Skip to first presentation context.
	off := dceHeaderSize + 8 + 4 // past max_xmit, max_recv, assoc_group, p_context_elem header

	if off+20 > len(pkt) {
		return false
	}

	// Skip context_id(2) + num_transfer(1) + pad(1) = 4 bytes.
	off += 4

	// Abstract syntax UUID (16 bytes) + version (4 bytes).
	if off+16 > len(pkt) {
		return false
	}

	uuid := formatUUID(pkt[off : off+16])
	meta.Endpoint = uuid

	// Look up well-known endpoint name.
	if name, ok := knownEndpoints[strings.ToLower(uuid)]; ok {
		meta.Endpoint = name
	}

	return true
}

// parseRequest extracts the operation number from an RPC request.
// After 16-byte header: alloc_hint(4) + context_id(2) + opnum(2).
func parseRequest(pkt []byte, meta *common.DCERPCMeta) bool {
	if len(pkt) < dceHeaderSize+8 {
		return false
	}

	opNum := binary.LittleEndian.Uint16(pkt[dceHeaderSize+6 : dceHeaderSize+8])
	meta.Operation = fmt.Sprintf("op_%d", opNum)

	// Map well-known operation numbers for known endpoints.
	if meta.Endpoint != "" {
		meta.Operation = mapOperation(meta.Endpoint, int(opNum))
	}

	return true
}

func findDCEHeader(data []byte) int {
	for i := 0; i+1 < len(data); i++ {
		if data[i] == 5 && data[i+1] == 0 {
			return i
		}
	}
	return -1
}

// formatUUID formats a 16-byte DCE UUID in standard form.
// DCE UUIDs are mixed-endian: first 3 components are little-endian.
func formatUUID(data []byte) string {
	if len(data) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(data[0:4]),
		binary.LittleEndian.Uint16(data[4:6]),
		binary.LittleEndian.Uint16(data[6:8]),
		data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15],
	)
}

// mapOperation returns a human-readable name for well-known operations.
func mapOperation(endpoint string, opNum int) string {
	ops := map[string]map[int]string{
		"svcctl": {
			0:  "CloseServiceHandle",
			7:  "OpenSCManager",
			12: "CreateServiceW",
			15: "OpenServiceW",
			23: "StartServiceW",
			24: "DeleteService",
		},
		"IWbemLoginClientID": {
			3: "NTLMLogin",
			6: "ExecQuery",
		},
		"samr": {
			5:  "LookupDomain",
			7:  "OpenDomain",
			13: "EnumerateUsersInDomain",
			34: "GetMembersInAlias",
		},
		"atsvc": {
			0: "NetrJobAdd",
			1: "NetrJobDel",
			2: "NetrJobEnum",
		},
		"srvsvc": {
			15: "NetShareEnumAll",
			16: "NetShareGetInfo",
		},
	}

	if endpointOps, ok := ops[endpoint]; ok {
		if name, ok := endpointOps[opNum]; ok {
			return name
		}
	}
	return fmt.Sprintf("op_%d", opNum)
}
