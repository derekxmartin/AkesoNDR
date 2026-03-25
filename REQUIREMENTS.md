# Akeso NDR — Requirements Document v1.0

**A Proof-of-Concept Network Detection & Response Platform**

Version 1.0 — Claude Code Implementation Phases | March 2026

Built in Go with gopacket for passive traffic analysis and protocol metadata extraction
Inspired by Vectra AI's NDR architecture: sensor-based capture, protocol dissection, behavioral detection, host scoring
Designed to ship ECS-normalized network telemetry to AkesoSIEM for cross-domain correlation

---

## PART I: REQUIREMENTS & ARCHITECTURE

---

## 1. Executive Summary

AkesoNDR is a proof-of-concept Network Detection and Response platform built in Go, using gopacket (libpcap bindings) for passive network traffic capture and protocol metadata extraction. Its purpose is to fill the network visibility gap in the Akeso portfolio by providing a dedicated network sensor that watches traffic on a SPAN port or network tap, extracts structured protocol metadata (DNS, HTTP, TLS, SMB, Kerberos, SSH, SMTP, RDP, NTLM, LDAP, DCE-RPC), applies behavioral detection rules for common network-based attack techniques, and ships ECS-normalized events to AkesoSIEM for cross-domain correlation.

The project is modeled after the architecture pioneered by Vectra AI — the market leader in NDR and a 2025 Gartner Magic Quadrant Leader — which uses a sensor/brain architecture where sensors passively capture traffic and extract metadata, while a central brain applies AI-driven behavioral detections and host-level threat scoring. AkesoNDR adapts this architecture to a portfolio-appropriate scope: instead of Vectra's proprietary ML models, AkesoNDR uses rule-based and statistical detection (beacon interval analysis, entropy scoring, threshold-based anomaly detection) with Sigma-compatible rule output to AkesoSIEM.

Where AkesoEDR sees what happens on the endpoint, and AkesoSIEM correlates events across sources, AkesoNDR sees what moves across the wire. Together they enable detection chains that no single tool can produce: EDR detects credential dumping on Host A → NDR detects SMB lateral movement from Host A to Host B → EDR detects process execution on Host B → NDR detects data exfiltration from Host B to an external IP. This is the cross-domain correlation story that separates enterprise security platforms from individual point tools.

## 2. Project Goals & Non-Goals

### 2.1 Goals

- Build a passive network sensor in Go that captures traffic via libpcap/gopacket on a configured interface, extracts structured protocol metadata for DNS, HTTP, TLS/SSL, SMB, Kerberos, SSH, SMTP, RDP, NTLM, LDAP, and DCE-RPC, and normalizes all metadata to the Elastic Common Schema (ECS).
- Implement a connection tracking engine that maintains state for TCP sessions, correlates request/response pairs, and computes per-session metadata (duration, bytes transferred, packet counts, connection state).
- Build a behavioral detection engine with rule-based detections for: C2 beaconing (interval regularity + jitter analysis), DNS tunneling (query entropy + subdomain length analysis), lateral movement patterns (SMB/RPC/WMI fan-out), data exfiltration (outbound volume anomalies), suspicious remote execution (PsExec, WMI, WinRM network signatures), Kerberos attacks (Kerberoasting, AS-REP roasting, Golden/Silver ticket indicators), and credential theft over the network (NTLM relay patterns, LDAP cleartext binds).
- Implement host-level threat scoring inspired by Vectra's threat + certainty model: aggregate per-host detections into a composite score that prioritizes hosts requiring analyst attention.
- Ship all network metadata events and detection alerts to AkesoSIEM via its HTTP ingest API as ECS-normalized JSON, with logsource `product: akeso_ndr` for Sigma rule targeting.
- Provide a PCAP evidence buffer (rolling ring buffer) that retains raw packets for a configurable window so that detection events can reference the triggering packet capture for analyst investigation.
- Expose a REST API for sensor health, detection status, host scores, and PCAP retrieval.
- Support Suricata-compatible rule loading (via EVE JSON output parsing or direct rule evaluation) for signature-based detection alongside behavioral detection — matching Vectra Match's hybrid approach.
- Build a minimal web dashboard showing: top scored hosts, active detections by MITRE ATT&CK tactic, protocol distribution, traffic volume trends, and sensor health.

### 2.2 Non-Goals (v1)

- Replacing Vectra AI, Darktrace, ExtraHop, or any production NDR. This is a learning and portfolio tool.
- Machine learning behavioral baselines. v1 is rule-based and statistical only. ML anomaly detection is a v2 roadmap item.
- Full packet storage or deep packet inspection of encrypted payloads. AkesoNDR works with metadata and unencrypted traffic.
- TLS decryption (MITM proxy). Encrypted traffic analysis uses JA3/JA4 fingerprinting, certificate metadata, and flow behavior.
- Inline/blocking mode. AkesoNDR is passive-only (SPAN/TAP), never inline.
- Multi-sensor distributed deployment. v1 is a single sensor with a local detection engine.

## 3. System Architecture

### 3.1 Component Overview

| Component | Language | Responsibility |
|-----------|----------|---------------|
| akeso-capture | Go | Packet capture engine using gopacket/libpcap. Reads from SPAN interface, reassembles TCP streams, dispatches to protocol parsers. Ring buffer for PCAP evidence. |
| akeso-protocols | Go | Protocol dissector library. Parses DNS, HTTP, TLS, SMB, Kerberos, SSH, SMTP, RDP, NTLM, LDAP, DCE-RPC. Extracts structured metadata per Vectra's metadata schema. |
| akeso-sessions | Go | Connection tracker. Maintains per-flow state (5-tuple), computes session metrics (duration, bytes, packets, conn_state), correlates with protocol metadata. |
| akeso-detect | Go | Behavioral detection engine. Beacon detector, DNS tunnel detector, lateral movement detector, exfiltration detector, Kerberos attack detector, NTLM abuse detector. Host scoring aggregator. |
| akeso-signatures | Go | Suricata-compatible signature engine. Loads ET Open / custom rules, evaluates against packet and session data, produces EVE-style alert events. |
| akeso-export | Go | SIEM exporter. Normalizes all metadata and alerts to ECS, batches and ships to AkesoSIEM HTTP ingest API. Manages API key auth and retry logic. |
| akeso-ndr-api | Go | REST API server. Host scores, detections, PCAP retrieval, sensor health, configuration. Serves the web dashboard. |
| akeso-ndr-dash | HTML/JS | Single-page dashboard. Host threat matrix, detection timeline, protocol breakdown, traffic trends, sensor health. |

### 3.2 Data Flow

```
[SPAN/TAP Interface]
    → [akeso-capture] (libpcap, TCP reassembly, ring buffer)
        → [akeso-protocols] (DNS, HTTP, TLS, SMB, Kerberos, ...)
            → [akeso-sessions] (connection tracking, flow metrics)
                → [akeso-detect] (behavioral rules, host scoring)
                → [akeso-signatures] (Suricata rule evaluation)
                    → [akeso-export] → AkesoSIEM /api/v1/ingest
                    → [akeso-ndr-api] → Dashboard / PCAP retrieval
```

### 3.3 Normalization — Elastic Common Schema (ECS)

All network metadata is normalized to ECS before export to AkesoSIEM. This ensures that Sigma rules in the SIEM can target NDR events using the same field names as EDR, AV, DLP, and Windows Event sources. Key ECS field groups:

| ECS Field Group | Fields |
|----------------|--------|
| event.* | event.kind, event.category (network), event.type, event.action, event.duration, event.dataset |
| source.* / destination.* | IP, port, domain, mac, bytes, packets, geo (if GeoIP enrichment enabled) |
| network.* | network.transport (tcp/udp/icmp), network.protocol (http/dns/tls/smb/...), network.direction (internal/external/inbound/outbound), network.bytes, network.community_id |
| dns.* | dns.question.name, dns.question.type, dns.answers.data, dns.response_code, dns.header_flags |
| http.* | http.request.method, http.request.body.bytes, http.response.status_code, http.response.body.bytes, url.full, user_agent.original |
| tls.* | tls.version, tls.cipher, tls.client.ja3, tls.server.ja3s, tls.client.server_name (SNI), tls.server.certificate, tls.client.ja4, tls.server.ja4s |
| smb.* | Custom extension: smb.version, smb.action, smb.filename, smb.path, smb.domain, smb.username |
| kerberos.* | Custom extension: kerberos.request_type, kerberos.client, kerberos.service, kerberos.cipher, kerberos.success, kerberos.error_code |
| ssh.* | ssh.client, ssh.server, ssh.hassh, ssh.hassh_server |
| threat.* | threat.technique.id, threat.technique.name, threat.tactic.id, threat.tactic.name (MITRE mapping) |
| ndr.* | Custom extension: ndr.detection.name, ndr.detection.severity, ndr.host_score.threat, ndr.host_score.certainty, ndr.beacon.interval_mean, ndr.beacon.interval_stddev, ndr.session.conn_state |

### 3.4 Network Community ID

Every session is tagged with a Community ID (community_id spec v1.0) — a deterministic hash of the flow 5-tuple that enables cross-tool correlation. If AkesoEDR or AkesoFW logs include Community IDs, AkesoSIEM can join NDR network sessions with endpoint process events and firewall decisions on the same flow.

### 3.5 PCAP Evidence Buffer

Inspired by Vectra's rolling buffer approach, AkesoNDR maintains a ring buffer of raw packets on disk. When a detection fires, the relevant packets (identified by flow 5-tuple and timestamp range) are extracted into a detection-specific PCAP file. The buffer stores up to the first 50 packets of each flow plus any packets that triggered a detection. Buffer size and retention are configurable (default: 1GB, ~30 min at moderate traffic). PCAPs are retrievable via the REST API for analyst investigation.

### 3.6 Host Threat Scoring

AkesoNDR maintains a per-host score inspired by Vectra's threat + certainty model. Each detection contributes a threat score (how dangerous is this behavior?) and a certainty score (how confident are we?). Scores are aggregated per host using a weighted sum that considers: number of distinct detection types, MITRE ATT&CK tactic progression (reconnaissance → lateral movement → exfiltration scores higher than isolated detections), recency weighting (recent detections score higher), and detection severity. Hosts are classified into quadrants: Low/Medium/High/Critical based on combined threat × certainty, mirroring Vectra's prioritization model.

### 3.7 Suricata Signature Integration

Following Vectra Match's hybrid approach of combining AI behavioral detection with traditional signature-based IDS, AkesoNDR supports loading Suricata-compatible rules (ET Open ruleset + custom rules). This provides known-threat detection (IOC matching, known malware signatures, CVE exploit patterns) alongside the behavioral detections for unknown threats. Signature alerts are normalized to the same ECS schema and contribute to host scoring.

## 4. Protocol Metadata Extraction

AkesoNDR extracts structured metadata for each supported protocol, modeled after the Vectra AI Platform's network metadata schema. Each protocol dissector produces typed Go structs that are then mapped to ECS fields for export. The following sections detail the metadata fields extracted per protocol.

### 4.1 DNS

| Field | Description |
|-------|-------------|
| query | Domain name subject of the query |
| qtype / qtype_name | Query type (A, AAAA, PTR, TXT, MX, CNAME, SRV) |
| qclass / qclass_name | Query class (typically IN / Internet) |
| answers | List of answer records (data, type, TTL) |
| rcode / rcode_name | Response code (NOERROR, NXDOMAIN, SERVFAIL, REFUSED) |
| AA / RD / RA / TC | Header flags: Authoritative, Recursion Desired/Available, Truncated |
| trans_id | 16-bit transaction identifier |
| proto | Transport protocol (TCP or UDP) |
| TTLs | List of TTL values from answer records |
| total_answers | Count of answer records |
| **entropy** | **NDR-computed:** Shannon entropy of query name (tunneling indicator) |
| **subdomain_depth** | **NDR-computed:** Number of subdomain levels (tunneling indicator) |
| **query_length** | **NDR-computed:** Character length of the query name |

### 4.2 HTTP

| Field | Description |
|-------|-------------|
| method | HTTP request method (GET, POST, PUT, DELETE, etc.) |
| uri | Request URI, truncated to 512 bytes |
| host | Value of the Host header |
| user_agent | Value of the User-Agent header, truncated to 512 bytes |
| referrer | Value of the Referer header |
| status_code | HTTP response status code |
| status_msg | HTTP response status message |
| request_body_len | Bytes in request payload |
| response_body_len | Bytes in response payload |
| orig_mime_types | Content-Type of request |
| resp_mime_types | Content-Type of response |
| cookie_vars | Cookie variable names (values stripped for privacy) |
| accept_encoding | Accept-Encoding header value |

### 4.3 TLS/SSL

| Field | Description |
|-------|-------------|
| version | Negotiated TLS version (TLS 1.0, 1.1, 1.2, 1.3) |
| cipher | Selected cipher suite |
| server_name (SNI) | Server Name Indication from ClientHello |
| ja3 / ja3s | JA3 hash of client / JA3S hash of server TLS parameters |
| ja4 / ja4s | JA4 fingerprints (enhanced successor to JA3) |
| subject / issuer | Server certificate subject and issuer DN |
| not_valid_before / after | Certificate validity period |
| san.dns | Subject Alternative Names (DNS entries) |
| established | Whether the TLS handshake completed successfully |
| next_protocol (ALPN) | Application-layer protocol negotiation result |
| client_extensions | List of TLS extensions offered by client |

### 4.4 SMB

| Field | Description |
|-------|-------------|
| version | SMB version (SMBv1, SMBv2, SMBv3) |
| action | File action (open, read, write, delete, rename, close) |
| name / path | Filename and tree path |
| domain / hostname | SMB server domain and client hostname |
| username | Authenticated username ($ suffix = machine account) |
| delete_on_close | Flag indicating if file marked for deletion on close |

### 4.5 Kerberos

| Field | Description |
|-------|-------------|
| request_type | AS (Authentication Service) or TGS (Ticket Granting Service) |
| client | Client principal name including realm |
| service | Requested service principal including realm |
| success | Whether the request succeeded |
| error_code / error_msg | Kerberos error code and message if failed |
| req_ciphers | Ordered list of encryption types requested by client |
| rep_cipher | Encryption type selected in the reply |
| ticket_cipher | Encryption type of the issued ticket |
| **account_privilege** | **NDR-computed:** Estimated privilege level (Low/Med/High) from service type |

### 4.6 SSH

| Field | Description |
|-------|-------------|
| client / server | Client and server version strings |
| hassh / hassh_server | HASSH fingerprints of client and server SSH parameters |
| cipher_alg | Negotiated encryption algorithm |
| kex_alg | Key exchange algorithm |
| mac_alg | Message authentication code algorithm |
| host_key_alg | Server host key algorithm |
| host_key | Server key fingerprint |
| version | SSH major version (1 or 2) |

### 4.7 Additional Protocols

AkesoNDR also extracts metadata for: **SMTP** (from, to, cc, subject, DKIM/DMARC/SPF status, TLS flag), **RDP** (client_name, cookie/username, client_build, desktop dimensions, keyboard layout), **NTLM** (domain, hostname, username, success/status), **LDAP** (base_object, query, query_scope, result_code, bind error counts, encrypted SASL payload counts), **DCE-RPC** (endpoint, operation, domain, hostname, username, RTT). Each produces ECS-normalized events with appropriate event.category and event.type values.

### 4.8 Session Connectivity Metadata

For every TCP/UDP session, the connection tracker produces session-level metadata independent of the application protocol. This includes: connection state (S0, S1, SF, REJ, RSTO, RSTR, etc. using Zeek's conn_state model), duration, bytes and packets in each direction, first-packet timestamps, VLAN IDs, JA4T/JA4TS TCP fingerprints, and service classification. This metadata is essential for the behavioral detection engine — beacon detection operates on session timing patterns, exfiltration detection on byte volume trends, and lateral movement detection on connection fan-out patterns.

## 5. Detection Requirements

AkesoNDR's detection engine implements rule-based and statistical detections mapped to MITRE ATT&CK. Each detection produces an alert with: detection name, severity (1-10), certainty (1-10), MITRE technique ID, source/destination hosts, matched evidence fields, and a PCAP reference. Detections feed the host scoring engine and are exported to AkesoSIEM as ECS-normalized alerts.

### 5.1 C2 Beaconing Detection

**MITRE: T1071 (Application Layer Protocol), T1573 (Encrypted Channel)**

Detect command-and-control beaconing by analyzing outbound session timing patterns. The detector maintains a per-destination session history and computes: mean inter-session interval, standard deviation of intervals (low jitter = high beacon confidence), coefficient of variation, session count over window, and consistency of payload sizes. A beacon score combines these features — regular intervals with low jitter and consistent sizes score highest. Configurable thresholds for minimum session count (default: 10), maximum jitter ratio (default: 0.2), and minimum duration window (default: 2 hours). Supports detection of both fixed-interval and jittered beacons by analyzing the distribution shape rather than requiring exact periodicity.

### 5.2 DNS Tunneling Detection

**MITRE: T1071.004 (DNS), T1048.003 (Exfiltration Over Unencrypted Protocol)**

Detect DNS-based data exfiltration and C2 by analyzing query characteristics: Shannon entropy of the query name (high entropy = encoded data), subdomain depth and length (deep/long subdomains = data smuggling), query volume per unique parent domain (high volume to a single domain = tunnel), TXT record query ratio (TXT records carry more payload), and NXDOMAIN response ratio. The detector aggregates these signals per parent domain over a sliding window and scores them. Known CDN and legitimate high-entropy domains are whitelistable.

### 5.3 Lateral Movement Detection

**MITRE: T1021 (Remote Services), T1570 (Lateral Tool Transfer)**

Detect internal host-to-host movement using SMB, RPC, WMI, WinRM, RDP, and SSH. The detector tracks: per-host connection fan-out (host connecting to many internal hosts it hasn't contacted before), SMB file operations to ADMIN$ and C$ shares (PsExec pattern), DCE-RPC endpoint access patterns (IWbemLoginClientID = WMI, svcctl = service creation), new RDP connections between workstations (workstation-to-workstation RDP is unusual), and temporal clustering of connections to multiple hosts within a short window. A lateral movement score aggregates these signals per source host.

### 5.4 Data Exfiltration Detection

**MITRE: T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol)**

Detect data staging and exfiltration by monitoring outbound transfer volumes. The detector computes: per-host outbound byte baseline over a rolling window, deviation from baseline (Z-score), ratio of bytes sent vs received per session (high send ratio = upload/exfil), large file transfers to external IPs (especially to IPs not previously contacted), and sustained high-throughput outbound sessions. Alerts trigger when outbound volume exceeds baseline by a configurable threshold (default: 3 standard deviations) or when absolute volume thresholds are exceeded.

### 5.5 Kerberos Attack Detection

**MITRE: T1558 (Steal or Forge Kerberos Tickets), T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting)**

Detect Kerberos-based credential attacks from network traffic: **Kerberoasting** — high volume of TGS-REQ requests for SPN-bearing services from a single source within a short window, especially when requesting RC4 encryption (etype 23). **AS-REP Roasting** — AS-REQ requests where the response uses RC4 encryption, indicating accounts with pre-authentication disabled. **Golden/Silver Ticket indicators** — TGS-REQ with unusual encryption types or ticket lifetimes, TGT reuse across services from unexpected sources. **Brute force** — high rate of Kerberos errors (KRB5KDC_ERR_PREAUTH_FAILED) from a single source.

### 5.6 NTLM & Credential Abuse Detection

**MITRE: T1557 (Adversary-in-the-Middle), T1003 (OS Credential Dumping)**

Detect credential-related network attacks: **NTLM relay patterns** — NTLM authentication where the NTLMv1/v2 challenge-response is forwarded to a different target than the original challenger. **LDAP cleartext bind** — LDAP simple bind operations over unencrypted connections (credential exposure). **Pass-the-hash indicators** — NTLM authentication from hosts that haven't performed a corresponding interactive logon (detected via absence of Kerberos AS-REQ from the source).

### 5.7 Suspicious Remote Execution Detection

**MITRE: T1569.002 (Service Execution), T1047 (WMI)**

Detect remote code execution patterns visible on the network: SMB writes to ADMIN$ followed by service creation via svcctl RPC (PsExec pattern), WMI remote execution via IWbemLoginClientID / IWbemServices DCE-RPC endpoints, WinRM/PowerShell Remoting over HTTP(S) to ports 5985/5986, and scheduled task creation via atsvc RPC. Each pattern produces a detection with the specific execution method identified.

### 5.8 Hidden Tunnel Detection

**MITRE: T1572 (Protocol Tunneling), T1573 (Encrypted Channel)**

Detect covert tunnels hidden within allowed protocols: HTTPS tunnels with anomalous session duration and byte patterns (long-lived connections with periodic small exchanges = C2 over HTTPS), HTTP tunnels with non-standard content patterns, DNS tunnels (covered in 5.2), and SSH tunnels with port forwarding indicators. Detection uses session metadata analysis — no payload decryption required.

### 5.9 Network Reconnaissance Detection

**MITRE: T1046 (Network Service Discovery), T1018 (Remote System Discovery)**

Detect port scanning and service enumeration: horizontal scans (one source, many destinations, same port), vertical scans (one source, one destination, many ports), slow scans (distributed over time to evade thresholds), and service probing (connections to well-known service ports with immediate disconnect or minimal data exchange). The detector uses connection state analysis — S0 (SYN with no reply) and REJ (rejected) states at scale indicate scanning.

### 5.10 Cross-Portfolio Detections (via AkesoSIEM)

While AkesoNDR generates network-only detections locally, the most powerful detections emerge when NDR events are correlated with EDR, AV, and DLP telemetry in AkesoSIEM. The following Sigma correlation rules ship with AkesoNDR for installation in AkesoSIEM:

- **EDR + NDR: Credential Theft → Lateral Movement** — EDR detects LSASS access on Host A → NDR detects SMB lateral movement from Host A to Host B within 30 minutes, correlated by source IP. (Full kill chain visibility.)
- **NDR + EDR: Network Beacon → Process Identification** — NDR detects C2 beaconing to external IP → correlated with EDR process telemetry on the beaconing host to identify the responsible process.
- **NDR + AV: Lateral Tool Transfer → Malware Detection** — NDR detects file transfer via SMB to a new host → AV detects the transferred file as malicious. Confirms the lateral movement carried malware.
- **NDR + DLP: Exfiltration Confirmation** — NDR detects high-volume outbound transfer → DLP previously classified accessed files as confidential. Confirms data exfiltration of sensitive material.
- **Full Chain: Recon → Credential Theft → Lateral Movement → Exfiltration** — NDR port scan detection → EDR credential dumping → NDR lateral movement → NDR data exfiltration, all correlated by host and timeframe.

## 6. AkesoSIEM Integration

### 6.1 Event Export

| Aspect | Requirement |
|--------|-------------|
| Protocol | HTTP POST to AkesoSIEM `/api/v1/ingest` with JSON body. |
| Authentication | API key in `X-API-Key` header. Key configured via akeso-ndr config. |
| Event format | ECS-normalized JSON. `source_type: akeso_ndr`. |
| Event types | `ndr:session` (connection metadata), `ndr:dns` / `ndr:http` / `ndr:tls` / `ndr:smb` / `ndr:kerberos` / etc. (protocol metadata), `ndr:detection` (behavioral alert), `ndr:signature` (Suricata match). |
| Batch support | NDJSON (newline-delimited JSON) for bulk ingestion. Default batch: 500 events or 5s flush. |
| Sigma logsource | `product: akeso_ndr`, category maps to protocol type. Sigma rules can target ndr events specifically or correlate across products. |

### 6.2 Host Score Export

Host scores are exported as periodic `ndr:host_score` events containing: host IP, hostname (if resolved), threat score (0-100), certainty score (0-100), quadrant (Low/Medium/High/Critical), active detection count, MITRE tactics observed, and score history (last 24h trend). AkesoSIEM can correlate host scores with EDR and DLP events to prioritize investigation across all data sources.

## 7. REST API & Dashboard

### 7.1 REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Sensor health: capture stats, packet drops, memory, detection engine status |
| `/api/v1/hosts` | GET | List monitored hosts with current threat/certainty scores, sortable/filterable |
| `/api/v1/hosts/{ip}` | GET | Host detail: score history, active detections, protocol breakdown, timeline |
| `/api/v1/detections` | GET | List active detections with filters (severity, type, host, MITRE tactic) |
| `/api/v1/detections/{id}` | GET | Detection detail with matched evidence, PCAP reference, MITRE mapping |
| `/api/v1/pcap/{id}` | GET | Download detection-specific PCAP file |
| `/api/v1/protocols` | GET | Protocol distribution statistics (session counts, bytes by protocol) |
| `/api/v1/signatures` | GET | Loaded Suricata rules and match counts |
| `/api/v1/signatures/reload` | POST | Hot-reload Suricata rules from disk |

### 7.2 Web Dashboard

Minimal SPA served by akeso-ndr-api: **Host Threat Matrix** — scatter plot of all hosts on threat (x) vs certainty (y) axes with quadrant coloring, inspired by Vectra's prioritization view. **Detection Timeline** — chronological view of detections color-coded by MITRE tactic. **Protocol Breakdown** — pie/bar chart of traffic by protocol. **Top Talkers** — hosts ranked by traffic volume and detection count. **Sensor Health** — packets captured, dropped, memory usage, detection engine latency.

## 8. Build & Development Environment

- **Language:** Go 1.22+
- **Key dependencies:** google/gopacket (libpcap bindings + TCP reassembly), go-elasticsearch (for host score storage if needed), chi (HTTP routing), zap (structured logging), go-yaml (config/rule loading)
- **Capture:** libpcap via gopacket. Requires libpcap-dev on build host.
- **Testing:** gopacket/pcapgo for reading PCAP files in tests (no live capture needed for unit/integration tests)
- **Dashboard:** Vanilla HTML/JS/CSS, no build step. Served by akeso-ndr-api.
- **Docker:** Dockerfile for sensor + docker-compose for test environment with traffic generation

## 9. Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Packet drops under high traffic | High | BPF filters to scope capture. Configurable snap length. Metrics on drop rate. Batch processing with buffered channels. |
| Protocol parsing edge cases | Medium | Test against PCAP corpus (Wireshark samples, Zeek test suite). Graceful degradation — unparseable packets logged to raw metadata. |
| False positive detections | Medium | Configurable thresholds per detection. Whitelist support for known benign patterns (CDNs, backup traffic, legitimate admin tools). |
| gopacket TCP reassembly limits | Medium | Configurable stream buffer limits. Timeout stale streams. Monitor memory usage. |
| PCAP buffer disk pressure | Low | Configurable max size with automatic oldest-first eviction. Health endpoint reports buffer utilization. |
| ECS mapping gaps | Low | Start with core fields. Preserve unmapped protocol fields in `labels.*`. Custom `ndr.*` extension fields for NDR-specific metadata. |

## 10. References

- Vectra AI Platform Documentation: docs.vectra.ai — Architecture, metadata schema, MITRE ATT&CK mapping reference.
- Vectra AI Network Metadata Attributes (Feb 2026) — Protocol field reference for Beacon, DNS, HTTP, TLS, SMB, Kerberos, SSH, SMTP, LDAP, DCE-RPC, NTLM, RDP, Radius.
- Vectra Match: Suricata-compatible signature integration alongside behavioral AI detection.
- gopacket: github.com/google/gopacket — Go packet processing library with libpcap bindings.
- Elastic Common Schema: elastic.co/docs/reference/ecs — Event normalization standard.
- Community ID Flow Hashing: github.com/corelight/community-id-spec — Deterministic flow identifier for cross-tool correlation.
- JA3/JA3S TLS fingerprinting: github.com/salesforce/ja3
- JA4+ fingerprinting: github.com/FoxIO-LLC/ja4
- HASSH SSH fingerprinting: github.com/salesforce/hassh
- SigmaHQ: github.com/SigmaHQ/sigma — Sigma detection rule format and community rules.
- ET Open Ruleset: rules.emergingthreats.net — Open-source Suricata/Snort signatures.
- MITRE ATT&CK: attack.mitre.org — Adversary tactics and techniques knowledge base.
- MITRE D3FEND: d3fend.mitre.org — Defensive technique countermeasures.
- Zeek (formerly Bro): zeek.org — Network analysis framework. Connection state model reference.
- Corelight Open NDR Platform — Zeek + Suricata + YARA reference architecture.

---

## PART II: IMPLEMENTATION PHASES

---

## 11. How To Use Part II With Claude Code

Same workflow as AkesoEDR, AkesoSIEM, and all other Akeso projects: each task has an ID, files, acceptance criteria, and complexity estimate (S/M/L/XL). Feed one phase at a time to Claude Code.

### Phase 0: Project Scaffolding

**Goal:** Monorepo, Go module, libpcap setup, shared types, config.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P0-T1 | Init Go module, directory structure, Makefile (build/test/run). | `go.mod`, `Makefile`, all `cmd/` + `internal/` dirs | `make build` compiles all binaries. | S |
| P0-T2 | Docker environment: Dockerfile for sensor, docker-compose with traffic generation (tcpreplay). | `Dockerfile`, `docker-compose.yml`, `scripts/` | `docker-compose up` → sensor starts, captures test traffic. | M |
| P0-T3 | Core types: SessionMeta, ProtocolMeta (per protocol), Detection, HostScore Go structs. JSON tags. | `internal/common/types.go`, `session.go`, `detection.go`, `host_score.go` | Compiles. Round-trip marshal/unmarshal. | M |
| P0-T4 | ECS event struct. All field groups from Section 3.3. Mapping functions from internal types to ECS. | `internal/common/ecs_event.go`, `ecs_mapper.go` | All field groups covered. SessionMeta → ECS round-trip. | M |
| P0-T5 | Config loading (TOML): capture interface, BPF filter, detection thresholds, SIEM endpoint, API settings. | `internal/config/config.go`, `akeso-ndr.toml` | Loads and validates. Missing required fields → clear errors. | M |

### Phase 1: Packet Capture & Connection Tracking

**Goal:** Live packet capture with TCP reassembly and session tracking.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P1-T1 | Packet capture engine using gopacket/pcap. Open interface, apply BPF filter, read packets into channel. | `internal/capture/engine.go`, `cmd/akeso-ndr/main.go` | Captures packets on configured interface. BPF filter applied. Metrics: pps, bps. | L |
| P1-T2 | TCP stream reassembly using gopacket/tcpassembly. Reassemble bidirectional streams, dispatch to protocol router. | `internal/capture/tcp_reassembly.go`, `stream_factory.go` | HTTP request/response pairs reassembled from PCAP. Bidirectional. | L |
| P1-T3 | Connection tracker. 5-tuple state table, session lifecycle (SYN → established → FIN/RST → closed), metrics per session. | `internal/sessions/tracker.go`, `conn_state.go` | Sessions tracked. Duration, bytes, packets, conn_state correct. Timeout stale flows. | L |
| P1-T4 | Community ID computation for each session. Tag all session metadata with community_id field. | `internal/sessions/community_id.go` | Community ID matches reference implementation for test vectors. | S |
| P1-T5 | PCAP ring buffer. Write raw packets to rolling files. Configurable max size. Extraction by flow 5-tuple + time range. | `internal/capture/pcap_buffer.go` | Buffer writes. Extraction produces valid PCAP. Eviction works at max size. | L |

### Phase 2: Protocol Dissectors — DNS & HTTP

**Goal:** Extract structured metadata for DNS and HTTP.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P2-T1 | DNS dissector. Parse DNS queries and responses (UDP + TCP). Extract all fields from Section 4.1. | `internal/protocols/dns/parser.go` | Parse sample DNS PCAP. All fields correct including entropy computation. | M |
| P2-T2 | HTTP dissector. Parse request/response from reassembled TCP streams. Extract all fields from Section 4.2. | `internal/protocols/http/parser.go` | Parse sample HTTP PCAP. Method, URI, status, headers, body lengths correct. | L |
| P2-T3 | Protocol router. Classify sessions by port + payload heuristics. Dispatch to correct dissector. | `internal/protocols/router.go` | DNS on 53 → DNS parser. HTTP on 80/8080 → HTTP parser. Unknown → raw session. | M |
| P2-T4 | End-to-end: capture → reassemble → dissect → session metadata. Validate against PCAP test corpus. | `tests/integration/dns_http_test.go` | 10 DNS + 10 HTTP sessions from PCAP → all metadata fields populated correctly. | M |

### Phase 3: Protocol Dissectors — TLS, SMB, Kerberos

**Goal:** Extract metadata for encrypted transport and Active Directory protocols.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P3-T1 | TLS dissector. Parse ClientHello/ServerHello, extract SNI, version, cipher, JA3/JA3S, JA4/JA4S, certificate fields. | `internal/protocols/tls/parser.go`, `ja3.go`, `ja4.go` | JA3 hashes match reference for sample TLS PCAPs. SNI, cert fields correct. | L |
| P3-T2 | SMB dissector. Parse SMBv1/v2/v3 negotiate, session setup, tree connect, file operations. | `internal/protocols/smb/parser.go` | Parse SMB file copy PCAP. Version, action, path, username all extracted. | L |
| P3-T3 | Kerberos dissector. Parse AS-REQ/AS-REP, TGS-REQ/TGS-REP. Extract encryption types, principals, errors. | `internal/protocols/kerberos/parser.go` | Parse Kerberos auth PCAP. Request type, client, service, ciphers correct. | L |
| P3-T4 | Integrate all Phase 3 dissectors into protocol router. Port + heuristic classification. | `internal/protocols/router.go` (extend) | TLS on 443, SMB on 445, Kerberos on 88 all route correctly. | S |

### Phase 4: Protocol Dissectors — SSH, SMTP, RDP, NTLM, LDAP, DCE-RPC

**Goal:** Complete protocol coverage for all Section 4 protocols.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P4-T1 | SSH dissector. Parse version exchange, extract client/server strings, compute HASSH fingerprints. | `internal/protocols/ssh/parser.go`, `hassh.go` | HASSH matches reference for sample SSH PCAPs. | M |
| P4-T2 | SMTP dissector. Parse SMTP envelope commands (HELO, MAIL FROM, RCPT TO), extract headers from DATA. | `internal/protocols/smtp/parser.go` | From, To, Subject, DKIM/SPF status extracted from sample SMTP PCAP. | M |
| P4-T3 | RDP dissector. Parse RDP negotiation (Cookie/username, client build, desktop dimensions). | `internal/protocols/rdp/parser.go` | Client name, cookie, dimensions extracted. Encrypted fields noted. | M |
| P4-T4 | NTLM dissector. Parse NTLM auth within SMB/HTTP. Extract domain, hostname, username, success. | `internal/protocols/ntlm/parser.go` | NTLM type 1/2/3 messages parsed. Username + domain correct. | M |
| P4-T5 | LDAP dissector. Parse LDAP bind, search, result. Extract base_object, query, result_code. | `internal/protocols/ldap/parser.go` | LDAP bind + search parsed. Cleartext bind detection flag set. | M |
| P4-T6 | DCE-RPC dissector. Parse bind, request, response. Extract endpoint, operation, UUID. | `internal/protocols/dcerpc/parser.go` | IWbemLoginClientID, svcctl, atsvc endpoints identified. | M |

### Phase 5: Behavioral Detection Engine

**Goal:** Core detection algorithms for C2, tunneling, lateral movement, exfiltration.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P5-T1 | Detection engine framework. Detection interface, registry, alert pipeline, MITRE mapping. | `internal/detect/engine.go`, `registry.go`, `alert.go`, `mitre.go` | Register detection. Feed events. Alert emitted with MITRE tags. | M |
| P5-T2 | C2 beacon detector. Session interval analysis, jitter computation, beacon scoring. | `internal/detect/beacon.go` | >10 sessions to same dest, CV < 0.2, consistent sizes → beacon alert. Random traffic → no alert. | XL |
| P5-T3 | DNS tunnel detector. Entropy scoring, subdomain analysis, volume aggregation per parent domain. | `internal/detect/dns_tunnel.go` | iodine/dnscat2 PCAP → tunnel alert. Normal DNS → no alert. | L |
| P5-T4 | Lateral movement detector. Internal fan-out tracking, SMB admin share access, DCE-RPC service creation patterns. | `internal/detect/lateral.go` | PsExec PCAP (ADMIN$ + svcctl) → lateral alert. Normal file server access → no alert. | L |
| P5-T5 | Exfiltration detector. Per-host outbound baseline, deviation scoring, upload ratio analysis. | `internal/detect/exfil.go` | Large outbound transfer (3+ stddev above baseline) → exfil alert. Normal browsing → no alert. | L |
| P5-T6 | Kerberos attack detector. Kerberoasting (TGS volume + RC4), AS-REP roasting, brute force. | `internal/detect/kerberos_attacks.go` | >20 TGS-REQ with etype 23 in 5min → Kerberoast alert. | L |
| P5-T7 | Port scan detector. Connection state analysis (S0/REJ fan-out), horizontal + vertical scan patterns. | `internal/detect/port_scan.go` | Nmap SYN scan PCAP → scan alert with port/host count. | M |

### Phase 6: Host Scoring Engine

**Goal:** Aggregate per-host detections into threat + certainty scores.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P6-T1 | Host score aggregator. Maintain per-host detection list, compute weighted threat + certainty scores. | `internal/detect/host_scorer.go` | Host with beacon + lateral = higher score than host with beacon only. | L |
| P6-T2 | MITRE tactic progression weighting. Hosts showing multi-stage attack progression score higher. | `internal/detect/tactic_weight.go` | Recon → Cred Access → Lateral → Exfil chain scores Critical. | M |
| P6-T3 | Score decay and expiration. Scores decay over time. Old detections contribute less. Configurable half-life. | `internal/detect/score_decay.go` | Detection from 24h ago contributes less than detection from 1h ago. | M |
| P6-T4 | Quadrant classification. Map threat × certainty to Low/Medium/High/Critical quadrants. | `internal/detect/quadrant.go` | Quadrant boundaries configurable. Default: Critical = both > 70. | S |

### Phase 7: Suricata Signature Integration

**Goal:** Load and evaluate Suricata-compatible rules alongside behavioral detections.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P7-T1 | Suricata rule parser. Parse SID, msg, content, flow, threshold directives from rule files. | `internal/signatures/parser.go`, `types.go` | Parse 100 ET Open rules without error. SID, msg, content extracted. | L |
| P7-T2 | Content matching engine. Evaluate content matches against packet payloads and session metadata. | `internal/signatures/matcher.go` | Content match with offset/depth/nocase works. Known malware PCAP → alert. | XL |
| P7-T3 | Rule loader with hot-reload. Load from configured directory, validate, atomic swap on reload. | `internal/signatures/loader.go` | New rule file → active in 10s. Invalid rule → rejected with error. | M |
| P7-T4 | Integrate signature alerts into host scoring and SIEM export pipeline. | `internal/signatures/pipeline.go` | Suricata alert → host score updated + ECS event exported to SIEM. | M |

### Phase 8: SIEM Export & ECS Normalization

**Goal:** Ship all network metadata and detections to AkesoSIEM.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P8-T1 | SIEM exporter. HTTP client for AkesoSIEM `/api/v1/ingest`. Batch NDJSON. API key auth. Retry with backoff. | `internal/export/siem_client.go` | 100 events batched and sent. 401 → clear error. Retry on 503. | M |
| P8-T2 | ECS normalization pipeline. Transform all internal types (SessionMeta, ProtocolMeta, Detection) to ECS JSON. | `internal/export/ecs_transform.go` | DNS event → correct `dns.*` + `network.*` + source/dest fields. Detection → `threat.*` mapping. | L |
| P8-T3 | Cross-portfolio Sigma rules. Write 5 rules for AkesoSIEM that correlate NDR + EDR + AV + DLP events. | `rules/akeso_cross_portfolio/` (5 `.yml` files) | Rules valid Sigma YAML. Logsource `product: akeso_ndr` targets correctly. | M |
| P8-T4 | Host score export. Periodic `ndr:host_score` events with threat, certainty, quadrant, active detections. | `internal/export/host_score_export.go` | Host scores appear in SIEM. Sortable by threat score. Quadrant correct. | S |

### Phase 9: REST API & Dashboard

**Goal:** Expose sensor data via REST API and minimal web dashboard.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P9-T1 | REST API server. All endpoints from Section 7.1. JSON responses. CORS. Pagination. | `internal/api/server.go`, `handlers.go`, `cmd/akeso-ndr-api/main.go` | All endpoints return correct JSON. PCAP download works. | M |
| P9-T2 | Host threat matrix page. Scatter plot of hosts on threat vs certainty axes. | `web/index.html`, `web/js/hosts.js` | Hosts plotted. Quadrant colors. Click for detail. | M |
| P9-T3 | Detection timeline page. Chronological detections color-coded by MITRE tactic. | `web/js/detections.js` | Detections display in order. Filter by tactic. Expand for detail. | M |
| P9-T4 | Sensor health + protocol breakdown. Capture stats, drop rate, protocol distribution charts. | `web/js/health.js`, `web/js/protocols.js` | Metrics accurate. Charts render. Auto-refresh. | M |

### Phase 10: Integration Testing

**Goal:** End-to-end validation with realistic traffic.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P10-T1 | Assemble test PCAP corpus. Include: normal browsing, C2 beaconing, DNS tunneling, lateral movement (PsExec), Kerberoasting, port scanning, data exfiltration, NTLM relay. | `tests/pcaps/` (8+ pcap files) | Each PCAP contains labeled traffic for specific detection scenario. | M |
| P10-T2 | Protocol parsing validation. Replay all PCAPs through full pipeline. Verify all protocol metadata fields populated. | `tests/integration/protocol_test.go` | All supported protocols parsed correctly across test corpus. | L |
| P10-T3 | Detection accuracy test. Replay attack PCAPs. Verify correct detections fire with correct MITRE mapping. Replay benign PCAPs. Verify no false positives. | `tests/integration/detection_test.go` | All attack scenarios detected. Zero FPs from benign traffic. | L |
| P10-T4 | SIEM export end-to-end. Replay PCAPs with AkesoSIEM running. Verify events and alerts appear in SIEM with correct ECS fields. Verify cross-portfolio Sigma rules evaluate correctly. | `tests/integration/siem_export_test.go` | Events in SIEM. Sigma rules fire on NDR events. Cross-portfolio correlation works. | L |
| P10-T5 | Host scoring end-to-end. Replay multi-stage attack PCAP. Verify host scores escalate through quadrants as attack progresses. | `tests/integration/host_score_test.go` | Host starts Low → detection → Medium → more detections → Critical. | M |

### Phase 11: Hardening & Performance

**Goal:** Production readiness and performance validation.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P11-T1 | Graceful shutdown. Drain capture, flush pending exports, save host scores, close PCAP buffer. | All `cmd/*/main.go` | SIGTERM → clean exit < 10s. No event loss. Host scores persisted. | M |
| P11-T2 | Prometheus metrics. Packets captured/dropped, sessions active, detections fired, export latency, host score distribution. | `internal/common/metrics.go` | Prometheus scrapes. Grafana template. Metrics accurate. | L |
| P11-T3 | Performance test. Replay high-volume PCAP (10k pps). Measure: packet drop rate, detection latency, memory usage. | `tests/benchmark/perf_test.go` | < 1% drops at 10k pps. Detection latency < 100ms. Memory stable. | L |
| P11-T4 | Whitelist and tuning framework. Per-detection whitelists (IP, domain, subnet). Global tuning for threshold adjustment. | `internal/detect/whitelist.go`, config tuning section | Whitelisted beacon dest → no alert. Threshold change → immediate effect. | M |

## Phase Summary

| Phase | Name | Tasks | Depends On | Focus |
|-------|------|-------|-----------|-------|
| P0 | Scaffolding | 5 | — | Foundation |
| P1 | Capture + Sessions | 5 | P0 | Packet Pipeline |
| P2 | DNS + HTTP Dissectors | 4 | P1 | Protocol Parsing |
| P3 | TLS + SMB + Kerberos | 4 | P1 | Protocol Parsing |
| P4 | SSH + SMTP + RDP + NTLM + LDAP + DCE-RPC | 6 | P1 | Protocol Parsing |
| P5 | Behavioral Detections | 7 | P2, P3, P4 | Detection |
| P6 | Host Scoring | 4 | P5 | Prioritization |
| P7 | Suricata Signatures | 4 | P1 | Detection |
| P8 | SIEM Export | 4 | P0–P7 | Integration |
| P9 | API + Dashboard | 4 | P5, P6 | Interface |
| P10 | Integration Tests | 5 | All | Validation |
| P11 | Hardening | 4 | All | Production |

**Total: 56 tasks, 12 phases. Estimated 40–60 Claude Code sessions.**

## Code Conventions

- **Go:** Go 1.22+. Standard library preferred. Errors wrapped with `fmt.Errorf`. Context propagation. Structured JSON logging (zap). Table-driven tests. Race detector in CI.
- **Packet Processing:** gopacket for all packet operations. TCP reassembly via gopacket/tcpassembly. PCAP test fixtures for all protocol parsers.
- **Detection Rules:** YAML-configured thresholds. Hot-reload support. Per-detection whitelist files. MITRE ATT&CK mapping required for all detections.
- **SIEM Export:** ECS-normalized JSON. Batch 500 events or 5s flush. Retry with exponential backoff. Community ID on every session event.
- **Dashboard:** Vanilla HTML/JS/CSS. No framework, no build step. REST API only. Functional over beautiful.

## v2 Roadmap

- ML behavioral baselines: per-host and per-subnet traffic profiling using statistical learning.
- Encrypted traffic analysis: TLS certificate graph analysis, flow behavior clustering for encrypted C2 detection.
- GeoIP enrichment: MaxMind GeoIP2 integration for geographic context on external IPs.
- Threat intelligence feed integration: STIX/TAXII feed ingestion for IOC matching against session metadata.
- Multi-sensor architecture: distributed sensors reporting to a central brain (AkesoSIEM or dedicated NDR brain).
- Cloud traffic sources: AWS VPC Flow Logs, Azure NSG Flow Logs, GCP Packet Mirroring as virtual sensor inputs.
- SOAR integration: automated response playbooks (trigger AkesoFW block on critical NDR alert).
- Full protocol decryption: optional TLS MITM proxy mode for deep inspection of encrypted traffic.
- PCAP-on-demand: selective full packet capture triggered by detection events (beyond the rolling buffer).
- EDR process correlation: query AkesoEDR for process context when NDR detects suspicious network activity from a host.