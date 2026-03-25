// Package sessions — community_id.go implements the Community ID Flow Hashing
// specification v1 (https://github.com/corelight/community-id-spec).
//
// A Community ID is a deterministic, direction-independent hash of a network
// flow's 5-tuple (src IP, dst IP, protocol, src port, dst port). It enables
// cross-tool correlation: if AkesoEDR, AkesoNDR, and firewall logs all tag
// events with the same Community ID, AkesoSIEM can join them on the same flow.
package sessions

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
)

// CommunityIDSeed is the default seed value (0). The spec allows a 16-bit
// seed to namespace hashes across sensors but the common default is 0.
const CommunityIDSeed uint16 = 0

// CommunityIDVersion is the spec version prefix.
const CommunityIDVersion = "1:"

// ICMP type-to-"port" mapping per the Community ID spec (Zeek convention).
// For ICMP, src_port = type, dst_port = code. To remove directionality the
// spec maps request types to their reply counterparts and always orders the
// "request" side first.
var icmpV4TypeMap = map[uint8]uint8{
	0:  8,  // Echo Reply → Echo Request
	8:  0,  // Echo Request → Echo Reply
	13: 14, // Timestamp → Timestamp Reply
	14: 13,
	15: 16, // Information Request → Information Reply
	16: 15,
	17: 18, // Address Mask Request → Address Mask Reply
	18: 17,
}

var icmpV6TypeMap = map[uint8]uint8{
	129: 128, // Echo Reply → Echo Request
	128: 129,
}

// CommunityID computes the Community ID v1 hash for a flow.
// For TCP/UDP/SCTP: srcPort and dstPort are the L4 ports.
// For ICMP: srcPort = ICMP type, dstPort = ICMP code.
func CommunityID(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8, seed uint16) string {
	// Normalize IPs to fixed-length representations.
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	var srcBytes, dstBytes []byte
	if src4 != nil && dst4 != nil {
		srcBytes = []byte(src4)
		dstBytes = []byte(dst4)
	} else {
		// IPv6 — ensure 16-byte form.
		srcBytes = []byte(srcIP.To16())
		dstBytes = []byte(dstIP.To16())
	}

	// For ICMP, apply type mapping for directionality removal.
	if proto == 1 { // ICMPv4
		srcPort, dstPort = icmpPorts(srcPort, dstPort, icmpV4TypeMap)
	} else if proto == 58 { // ICMPv6
		srcPort, dstPort = icmpPorts(srcPort, dstPort, icmpV6TypeMap)
	}

	// Order endpoints: smaller IP first; if equal, smaller port first.
	if shouldSwap(srcBytes, dstBytes, srcPort, dstPort) {
		srcBytes, dstBytes = dstBytes, srcBytes
		srcPort, dstPort = dstPort, srcPort
	}

	// Build the hash input:
	//   seed (2 bytes) | src_ip | dst_ip | proto (1 byte) | pad (1 byte) | src_port (2 bytes) | dst_port (2 bytes)
	bufLen := 2 + len(srcBytes) + len(dstBytes) + 1 + 1 + 2 + 2
	buf := make([]byte, 0, bufLen)

	// Seed (network byte order = big-endian).
	seedBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(seedBytes, seed)
	buf = append(buf, seedBytes...)

	// IPs (already in network byte order from net.IP).
	buf = append(buf, srcBytes...)
	buf = append(buf, dstBytes...)

	// Protocol + padding.
	buf = append(buf, proto, 0)

	// Ports (network byte order).
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, srcPort)
	buf = append(buf, portBytes...)
	binary.BigEndian.PutUint16(portBytes, dstPort)
	buf = append(buf, portBytes...)

	// SHA-1 → base64.
	hash := sha1.Sum(buf)
	b64 := base64.StdEncoding.EncodeToString(hash[:])

	return fmt.Sprintf("%s%s", CommunityIDVersion, b64)
}

// CommunityIDFromFlow is a convenience wrapper that computes the Community ID
// from a FlowKey (as used in the connection tracker).
func CommunityIDFromFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) string {
	return CommunityID(srcIP, dstIP, srcPort, dstPort, proto, CommunityIDSeed)
}

// shouldSwap returns true if the src/dst should be swapped to achieve
// canonical ordering (smaller IP first, then smaller port as tiebreaker).
func shouldSwap(srcIP, dstIP []byte, srcPort, dstPort uint16) bool {
	for i := 0; i < len(srcIP) && i < len(dstIP); i++ {
		if srcIP[i] < dstIP[i] {
			return false
		}
		if srcIP[i] > dstIP[i] {
			return true
		}
	}
	// IPs are equal — compare ports.
	return srcPort > dstPort
}

// icmpPorts normalizes ICMP type/code into directional ports using the
// type mapping table. If the type is a "reply" type, swap so the request
// type is always the src_port side.
func icmpPorts(typ, code uint16, typeMap map[uint8]uint8) (uint16, uint16) {
	if mapped, ok := typeMap[uint8(typ)]; ok {
		// If the mapped value is less than the type, this is a reply —
		// use the request type as src_port.
		if mapped < uint8(typ) {
			return uint16(mapped), code
		}
	}
	return typ, code
}
