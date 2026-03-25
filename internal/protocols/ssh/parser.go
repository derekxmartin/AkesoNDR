// Package ssh implements the AkesoNDR SSH protocol dissector.
//
// It parses SSH version exchange strings from the start of TCP streams and
// computes HASSH/HASSH-server fingerprints (MD5 of key exchange init params).
// The version string is the first line of an SSH connection: "SSH-2.0-OpenSSH_8.9".
// HASSH fingerprinting uses the Key Exchange Init (SSH_MSG_KEXINIT, type 20)
// message to build a fingerprint from kex_algorithms, encryption_algorithms,
// mac_algorithms, and compression_algorithms.
package ssh

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"strings"

	"github.com/akesondr/akeso-ndr/internal/common"
)

const (
	sshPrefix    = "SSH-"
	msgKEXInit   = 20 // SSH_MSG_KEXINIT
)

// Parser extracts SSH metadata from reassembled TCP streams.
type Parser struct{}

// NewParser creates an SSH parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts SSHMeta from client and server stream data.
// Returns nil if the data does not contain SSH traffic.
func (p *Parser) Parse(client, server []byte) *common.SSHMeta {
	clientVer := extractVersionString(client)
	serverVer := extractVersionString(server)

	if clientVer == "" && serverVer == "" {
		return nil
	}

	meta := &common.SSHMeta{
		Client: clientVer,
		Server: serverVer,
	}

	// Determine SSH version from version strings.
	if strings.HasPrefix(clientVer, "SSH-2.0") || strings.HasPrefix(serverVer, "SSH-2.0") {
		meta.Version = 2
	} else if strings.HasPrefix(clientVer, "SSH-1") || strings.HasPrefix(serverVer, "SSH-1") {
		meta.Version = 1
	}

	// Compute HASSH from client KEXINIT.
	if kexInit := findKEXInit(client); kexInit != nil {
		meta.HASSH = computeHASSH(kexInit)
		if len(kexInit.kexAlgs) > 0 {
			meta.KexAlg = kexInit.kexAlgs[0]
		}
		if len(kexInit.cipherAlgs) > 0 {
			meta.CipherAlg = kexInit.cipherAlgs[0]
		}
		if len(kexInit.macAlgs) > 0 {
			meta.MACAlg = kexInit.macAlgs[0]
		}
	}

	// Compute HASSH-server from server KEXINIT.
	if kexInit := findKEXInit(server); kexInit != nil {
		meta.HASSHServer = computeHASSH(kexInit)
		if len(kexInit.hostKeyAlgs) > 0 {
			meta.HostKeyAlg = kexInit.hostKeyAlgs[0]
		}
	}

	return meta
}

// CanParse returns true if the data starts with an SSH version string.
func (p *Parser) CanParse(client []byte) bool {
	return bytes.HasPrefix(client, []byte(sshPrefix))
}

// ---------------------------------------------------------------------------
// Version string extraction
// ---------------------------------------------------------------------------

func extractVersionString(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// SSH version string is the first line, terminated by \r\n or \n.
	end := bytes.IndexByte(data, '\n')
	if end < 0 {
		if len(data) > 255 {
			return ""
		}
		end = len(data)
	}
	line := string(data[:end])
	line = strings.TrimRight(line, "\r\n")

	if !strings.HasPrefix(line, sshPrefix) {
		return ""
	}

	// Sanity: version strings shouldn't be too long.
	if len(line) > 255 {
		line = line[:255]
	}
	return line
}

// ---------------------------------------------------------------------------
// KEXINIT parsing for HASSH
// ---------------------------------------------------------------------------

type kexInitMsg struct {
	kexAlgs     []string
	hostKeyAlgs []string
	cipherAlgs  []string
	macAlgs     []string
	compAlgs    []string
}

// findKEXInit searches for SSH_MSG_KEXINIT (type 20) in the stream data
// and parses the name-list fields.
func findKEXInit(data []byte) *kexInitMsg {
	// KEXINIT follows the version string and any banner. Look for the
	// SSH binary packet: length(4) + padding_length(1) + type(1=20) + cookie(16) + name-lists...
	for i := 0; i+6 < len(data); i++ {
		// Check for potential packet: length field + type=20.
		if i+4 >= len(data) {
			break
		}
		pktLen := int(data[i])<<24 | int(data[i+1])<<16 | int(data[i+2])<<8 | int(data[i+3])
		if pktLen < 22 || pktLen > 35000 { // reasonable KEXINIT size
			continue
		}
		if i+5 >= len(data) {
			continue
		}
		paddingLen := int(data[i+4])
		_ = paddingLen

		if i+5 >= len(data) {
			continue
		}
		msgType := data[i+5]
		if msgType != msgKEXInit {
			continue
		}

		// Found KEXINIT. Cookie is 16 bytes after msg type.
		nameListStart := i + 6 + 16 // past length(4) + padding_len(1) + type(1) + cookie(16)
		if nameListStart >= len(data) {
			continue
		}

		msg := &kexInitMsg{}
		off := nameListStart

		// Parse 5 name-lists: kex, host_key, cipher_c2s, mac_c2s, comp_c2s.
		// (We skip the server→client lists as HASSH uses client→server.)
		var nameList string
		nameList, off = readNameList(data, off)
		msg.kexAlgs = splitNames(nameList)

		nameList, off = readNameList(data, off)
		msg.hostKeyAlgs = splitNames(nameList)

		// cipher_algorithms_client_to_server
		nameList, off = readNameList(data, off)
		msg.cipherAlgs = splitNames(nameList)

		// cipher_algorithms_server_to_client (skip for HASSH)
		_, off = readNameList(data, off)

		// mac_algorithms_client_to_server
		nameList, off = readNameList(data, off)
		msg.macAlgs = splitNames(nameList)

		// mac_algorithms_server_to_client (skip)
		_, off = readNameList(data, off)

		// compression_algorithms_client_to_server
		nameList, off = readNameList(data, off)
		msg.compAlgs = splitNames(nameList)

		if len(msg.kexAlgs) > 0 {
			return msg
		}
	}
	return nil
}

func readNameList(data []byte, off int) (string, int) {
	if off+4 > len(data) {
		return "", off
	}
	listLen := int(data[off])<<24 | int(data[off+1])<<16 | int(data[off+2])<<8 | int(data[off+3])
	off += 4
	if listLen < 0 || off+listLen > len(data) {
		return "", off
	}
	s := string(data[off : off+listLen])
	return s, off + listLen
}

func splitNames(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// computeHASSH computes the HASSH fingerprint.
// HASSH = md5(kex_algorithms;encryption_algorithms;mac_algorithms;compression_algorithms)
func computeHASSH(msg *kexInitMsg) string {
	raw := fmt.Sprintf("%s;%s;%s;%s",
		strings.Join(msg.kexAlgs, ","),
		strings.Join(msg.cipherAlgs, ","),
		strings.Join(msg.macAlgs, ","),
		strings.Join(msg.compAlgs, ","),
	)
	hash := md5.Sum([]byte(raw))
	return fmt.Sprintf("%x", hash[:])
}
