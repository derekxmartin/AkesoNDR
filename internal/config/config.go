// Package config handles TOML configuration loading and validation for AkesoNDR.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level AkesoNDR configuration.
type Config struct {
	Capture    CaptureConfig    `toml:"capture"`
	Sessions   SessionsConfig   `toml:"sessions"`
	Detection  DetectionConfig  `toml:"detection"`
	Signatures SignaturesConfig `toml:"signatures"`
	Export     ExportConfig     `toml:"export"`
	API        APIConfig        `toml:"api"`
	PcapBuffer PcapBufferConfig `toml:"pcap_buffer"`
	Logging    LoggingConfig    `toml:"logging"`
}

// CaptureConfig controls packet capture behavior.
type CaptureConfig struct {
	Interface  string `toml:"interface"`
	BPFFilter  string `toml:"bpf_filter"`
	SnapLen    int    `toml:"snap_len"`
	Promisc    bool   `toml:"promiscuous"`
	BufferSize int    `toml:"buffer_size_mb"`
}

// SessionsConfig controls connection tracking.
type SessionsConfig struct {
	TCPTimeout     Duration `toml:"tcp_timeout"`
	UDPTimeout     Duration `toml:"udp_timeout"`
	MaxConcurrent  int      `toml:"max_concurrent"`
	CleanupInterval Duration `toml:"cleanup_interval"`
}

// DetectionConfig holds thresholds for each behavioral detector.
type DetectionConfig struct {
	Beacon      BeaconConfig      `toml:"beacon"`
	DNSTunnel   DNSTunnelConfig   `toml:"dns_tunnel"`
	LateralMove LateralMoveConfig `toml:"lateral_movement"`
	Exfil       ExfilConfig       `toml:"exfiltration"`
	Kerberos    KerberosConfig    `toml:"kerberos"`
	Scan        ScanConfig        `toml:"scan"`
}

// BeaconConfig holds C2 beacon detection thresholds.
type BeaconConfig struct {
	MinSessions    int      `toml:"min_sessions"`
	MaxJitterRatio float64  `toml:"max_jitter_ratio"`
	MinDuration    Duration `toml:"min_duration"`
}

// DNSTunnelConfig holds DNS tunneling detection thresholds.
type DNSTunnelConfig struct {
	EntropyThreshold    float64 `toml:"entropy_threshold"`
	MaxSubdomainDepth   int     `toml:"max_subdomain_depth"`
	QueryVolumeThreshold int    `toml:"query_volume_threshold"`
}

// LateralMoveConfig holds lateral movement detection thresholds.
type LateralMoveConfig struct {
	FanOutThreshold  int      `toml:"fan_out_threshold"`
	TimeWindow       Duration `toml:"time_window"`
}

// ExfilConfig holds data exfiltration detection thresholds.
type ExfilConfig struct {
	BaselineWindow      Duration `toml:"baseline_window"`
	DeviationThreshold  float64  `toml:"deviation_threshold"`
	AbsoluteThresholdMB int      `toml:"absolute_threshold_mb"`
}

// KerberosConfig holds Kerberos attack detection thresholds.
type KerberosConfig struct {
	TGSRequestThreshold int      `toml:"tgs_request_threshold"`
	TimeWindow          Duration `toml:"time_window"`
}

// ScanConfig holds port scan detection thresholds.
type ScanConfig struct {
	PortThreshold int      `toml:"port_threshold"`
	HostThreshold int      `toml:"host_threshold"`
	TimeWindow    Duration `toml:"time_window"`
}

// SignaturesConfig controls Suricata rule loading.
type SignaturesConfig struct {
	Enabled  bool     `toml:"enabled"`
	RuleDirs []string `toml:"rule_dirs"`
}

// ExportConfig controls SIEM event export.
type ExportConfig struct {
	SIEMEndpoint string   `toml:"siem_endpoint"`
	APIKey       string   `toml:"api_key"`
	BatchSize    int      `toml:"batch_size"`
	FlushInterval Duration `toml:"flush_interval"`
	MaxRetries   int      `toml:"max_retries"`
}

// APIConfig controls the REST API server.
type APIConfig struct {
	ListenAddr string `toml:"listen_addr"`
	EnableDash bool   `toml:"enable_dashboard"`
}

// PcapBufferConfig controls the PCAP evidence ring buffer.
type PcapBufferConfig struct {
	MaxSizeMB     int      `toml:"max_size_mb"`
	Retention     Duration `toml:"retention"`
	StoragePath   string   `toml:"storage_path"`
	MaxFlowPackets int     `toml:"max_flow_packets"`
}

// LoggingConfig controls structured logging.
type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"` // "json" or "console"
}

// ---------------------------------------------------------------------------
// Loading & Validation
// ---------------------------------------------------------------------------

// Load reads and parses an AkesoNDR TOML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}

	return cfg, nil
}

// Validate checks required fields and value ranges.
func (c *Config) Validate() error {
	if c.Capture.Interface == "" {
		return fmt.Errorf("capture.interface is required")
	}
	if c.Capture.SnapLen <= 0 {
		return fmt.Errorf("capture.snap_len must be positive, got %d", c.Capture.SnapLen)
	}
	if c.API.ListenAddr == "" {
		return fmt.Errorf("api.listen_addr is required")
	}
	if c.PcapBuffer.MaxSizeMB <= 0 {
		return fmt.Errorf("pcap_buffer.max_size_mb must be positive, got %d", c.PcapBuffer.MaxSizeMB)
	}
	if c.Detection.Beacon.MinSessions <= 0 {
		return fmt.Errorf("detection.beacon.min_sessions must be positive, got %d", c.Detection.Beacon.MinSessions)
	}
	if c.Detection.Beacon.MaxJitterRatio < 0 || c.Detection.Beacon.MaxJitterRatio > 1 {
		return fmt.Errorf("detection.beacon.max_jitter_ratio must be 0.0–1.0, got %f", c.Detection.Beacon.MaxJitterRatio)
	}
	return nil
}

// DefaultConfig returns a Config with sensible defaults for all fields.
func DefaultConfig() *Config {
	return &Config{
		Capture: CaptureConfig{
			SnapLen:    65535,
			Promisc:    true,
			BufferSize: 64,
		},
		Sessions: SessionsConfig{
			TCPTimeout:      Duration(5 * time.Minute),
			UDPTimeout:      Duration(2 * time.Minute),
			MaxConcurrent:   100000,
			CleanupInterval: Duration(30 * time.Second),
		},
		Detection: DetectionConfig{
			Beacon:      BeaconConfig{MinSessions: 10, MaxJitterRatio: 0.2, MinDuration: Duration(2 * time.Hour)},
			DNSTunnel:   DNSTunnelConfig{EntropyThreshold: 3.5, MaxSubdomainDepth: 5, QueryVolumeThreshold: 100},
			LateralMove: LateralMoveConfig{FanOutThreshold: 5, TimeWindow: Duration(15 * time.Minute)},
			Exfil:       ExfilConfig{BaselineWindow: Duration(1 * time.Hour), DeviationThreshold: 3.0, AbsoluteThresholdMB: 500},
			Kerberos:    KerberosConfig{TGSRequestThreshold: 10, TimeWindow: Duration(5 * time.Minute)},
			Scan:        ScanConfig{PortThreshold: 50, HostThreshold: 25, TimeWindow: Duration(5 * time.Minute)},
		},
		Signatures: SignaturesConfig{
			Enabled:  false,
			RuleDirs: []string{"/etc/akeso-ndr/rules"},
		},
		Export: ExportConfig{
			BatchSize:     500,
			FlushInterval: Duration(5 * time.Second),
			MaxRetries:    3,
		},
		API: APIConfig{
			ListenAddr: ":8080",
			EnableDash: true,
		},
		PcapBuffer: PcapBufferConfig{
			MaxSizeMB:      1024,
			Retention:       Duration(30 * time.Minute),
			StoragePath:    "/var/lib/akeso-ndr/pcap",
			MaxFlowPackets: 50,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// ---------------------------------------------------------------------------
// Duration — TOML-friendly time.Duration wrapper
// ---------------------------------------------------------------------------

// Duration wraps time.Duration for TOML string unmarshaling (e.g. "5m", "2h").
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// Duration returns the underlying time.Duration.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}
