package common

import "time"

// ---------------------------------------------------------------------------
// DNS Metadata (Section 4.1)
// ---------------------------------------------------------------------------

// DNSAnswer represents a single DNS answer record.
type DNSAnswer struct {
	Data string `json:"data"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
}

// DNSMeta holds extracted metadata from a DNS query/response pair.
type DNSMeta struct {
	Query         string      `json:"query"`
	QType         uint16      `json:"qtype"`
	QTypeName     string      `json:"qtype_name"`
	QClass        uint16      `json:"qclass"`
	QClassName    string      `json:"qclass_name"`
	Answers       []DNSAnswer `json:"answers,omitempty"`
	RCode         uint16      `json:"rcode"`
	RCodeName     string      `json:"rcode_name"`
	AA            bool        `json:"aa"`
	RD            bool        `json:"rd"`
	RA            bool        `json:"ra"`
	TC            bool        `json:"tc"`
	TransID       uint16      `json:"trans_id"`
	Proto         string      `json:"proto"` // "tcp" or "udp"
	TTLs          []uint32    `json:"ttls,omitempty"`
	TotalAnswers  int         `json:"total_answers"`
	Entropy       float64     `json:"entropy"`        // NDR-computed: Shannon entropy
	SubdomainDepth int        `json:"subdomain_depth"` // NDR-computed
	QueryLength   int         `json:"query_length"`    // NDR-computed
}

// ---------------------------------------------------------------------------
// HTTP Metadata (Section 4.2)
// ---------------------------------------------------------------------------

// HTTPMeta holds extracted metadata from an HTTP request/response pair.
type HTTPMeta struct {
	Method          string   `json:"method"`
	URI             string   `json:"uri"`
	Host            string   `json:"host"`
	UserAgent       string   `json:"user_agent,omitempty"`
	Referrer        string   `json:"referrer,omitempty"`
	StatusCode      int      `json:"status_code"`
	StatusMsg       string   `json:"status_msg,omitempty"`
	RequestBodyLen  int64    `json:"request_body_len"`
	ResponseBodyLen int64    `json:"response_body_len"`
	OrigMIMETypes   string   `json:"orig_mime_types,omitempty"`
	RespMIMETypes   string   `json:"resp_mime_types,omitempty"`
	CookieVars      []string `json:"cookie_vars,omitempty"`
	AcceptEncoding  string   `json:"accept_encoding,omitempty"`
}

// ---------------------------------------------------------------------------
// TLS/SSL Metadata (Section 4.3)
// ---------------------------------------------------------------------------

// TLSMeta holds extracted metadata from a TLS handshake.
type TLSMeta struct {
	Version          string    `json:"version"`
	Cipher           string    `json:"cipher"`
	ServerName       string    `json:"server_name"`        // SNI
	JA3              string    `json:"ja3,omitempty"`
	JA3S             string    `json:"ja3s,omitempty"`
	JA4              string    `json:"ja4,omitempty"`
	JA4S             string    `json:"ja4s,omitempty"`
	Subject          string    `json:"subject,omitempty"`
	Issuer           string    `json:"issuer,omitempty"`
	NotValidBefore   time.Time `json:"not_valid_before,omitempty"`
	NotValidAfter    time.Time `json:"not_valid_after,omitempty"`
	SANDNSNames      []string  `json:"san_dns,omitempty"`
	Established      bool      `json:"established"`
	NextProtocol     string    `json:"next_protocol,omitempty"` // ALPN
	ClientExtensions []uint16  `json:"client_extensions,omitempty"`
}

// ---------------------------------------------------------------------------
// SMB Metadata (Section 4.4)
// ---------------------------------------------------------------------------

// SMBMeta holds extracted metadata from SMB file operations.
type SMBMeta struct {
	Version       string `json:"version"` // SMBv1, SMBv2, SMBv3
	Action        string `json:"action"`  // open, read, write, delete, rename, close
	Name          string `json:"name,omitempty"`
	Path          string `json:"path,omitempty"`
	Domain        string `json:"domain,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	Username      string `json:"username,omitempty"`
	DeleteOnClose bool   `json:"delete_on_close"`
}

// ---------------------------------------------------------------------------
// Kerberos Metadata (Section 4.5)
// ---------------------------------------------------------------------------

// KerberosMeta holds extracted metadata from Kerberos exchanges.
type KerberosMeta struct {
	RequestType      string   `json:"request_type"` // "AS" or "TGS"
	Client           string   `json:"client"`
	Service          string   `json:"service"`
	Success          bool     `json:"success"`
	ErrorCode        int      `json:"error_code,omitempty"`
	ErrorMsg         string   `json:"error_msg,omitempty"`
	ReqCiphers       []int    `json:"req_ciphers,omitempty"`
	RepCipher        int      `json:"rep_cipher,omitempty"`
	TicketCipher     int      `json:"ticket_cipher,omitempty"`
	AccountPrivilege string   `json:"account_privilege,omitempty"` // NDR-computed: Low/Med/High
}

// ---------------------------------------------------------------------------
// SSH Metadata (Section 4.6)
// ---------------------------------------------------------------------------

// SSHMeta holds extracted metadata from SSH handshakes.
type SSHMeta struct {
	Client      string `json:"client"`
	Server      string `json:"server"`
	HASSH       string `json:"hassh,omitempty"`
	HASSHServer string `json:"hassh_server,omitempty"`
	CipherAlg   string `json:"cipher_alg,omitempty"`
	KexAlg      string `json:"kex_alg,omitempty"`
	MACAlg      string `json:"mac_alg,omitempty"`
	HostKeyAlg  string `json:"host_key_alg,omitempty"`
	HostKey     string `json:"host_key,omitempty"`
	Version     int    `json:"version"` // 1 or 2
}

// ---------------------------------------------------------------------------
// SMTP Metadata (Section 4.7)
// ---------------------------------------------------------------------------

// SMTPMeta holds extracted metadata from SMTP transactions.
type SMTPMeta struct {
	From       string   `json:"from"`
	To         []string `json:"to"`
	CC         []string `json:"cc,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	DKIMStatus string   `json:"dkim_status,omitempty"`
	DMARCStatus string  `json:"dmarc_status,omitempty"`
	SPFStatus  string   `json:"spf_status,omitempty"`
	TLS        bool     `json:"tls"`
}

// ---------------------------------------------------------------------------
// RDP Metadata (Section 4.7)
// ---------------------------------------------------------------------------

// RDPMeta holds extracted metadata from RDP sessions.
type RDPMeta struct {
	ClientName     string `json:"client_name,omitempty"`
	Cookie         string `json:"cookie,omitempty"` // username
	ClientBuild    string `json:"client_build,omitempty"`
	DesktopWidth   int    `json:"desktop_width,omitempty"`
	DesktopHeight  int    `json:"desktop_height,omitempty"`
	KeyboardLayout string `json:"keyboard_layout,omitempty"`
}

// ---------------------------------------------------------------------------
// NTLM Metadata (Section 4.7)
// ---------------------------------------------------------------------------

// NTLMMeta holds extracted metadata from NTLM authentication exchanges.
type NTLMMeta struct {
	Domain   string `json:"domain"`
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	Success  bool   `json:"success"`
	Status   string `json:"status,omitempty"`
}

// ---------------------------------------------------------------------------
// LDAP Metadata (Section 4.7)
// ---------------------------------------------------------------------------

// LDAPMeta holds extracted metadata from LDAP operations.
type LDAPMeta struct {
	BaseObject     string `json:"base_object,omitempty"`
	Query          string `json:"query,omitempty"`
	QueryScope     string `json:"query_scope,omitempty"`
	ResultCode     int    `json:"result_code"`
	BindErrorCount int    `json:"bind_error_count,omitempty"`
	SASLPayloads   int    `json:"sasl_payloads,omitempty"` // Encrypted SASL payload count
}

// ---------------------------------------------------------------------------
// DCE-RPC Metadata (Section 4.7)
// ---------------------------------------------------------------------------

// DCERPCMeta holds extracted metadata from DCE-RPC operations.
type DCERPCMeta struct {
	Endpoint  string        `json:"endpoint"`
	Operation string        `json:"operation"`
	Domain    string        `json:"domain,omitempty"`
	Hostname  string        `json:"hostname,omitempty"`
	Username  string        `json:"username,omitempty"`
	RTT       time.Duration `json:"rtt,omitempty"`
}
