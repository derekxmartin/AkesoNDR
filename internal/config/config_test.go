package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_ValidConfig(t *testing.T) {
	content := `
[capture]
interface = "eth0"
snap_len  = 65535

[sessions]
tcp_timeout = "5m"

[detection.beacon]
min_sessions     = 10
max_jitter_ratio = 0.2
min_duration     = "2h"

[api]
listen_addr = ":8080"

[pcap_buffer]
max_size_mb = 1024
storage_path = "/tmp/pcap"
`
	cfg := loadFromString(t, content)

	if cfg.Capture.Interface != "eth0" {
		t.Errorf("capture.interface: got %q, want %q", cfg.Capture.Interface, "eth0")
	}
	if cfg.Capture.SnapLen != 65535 {
		t.Errorf("capture.snap_len: got %d, want 65535", cfg.Capture.SnapLen)
	}
	if cfg.Sessions.TCPTimeout.Duration() != 5*time.Minute {
		t.Errorf("sessions.tcp_timeout: got %v, want 5m", cfg.Sessions.TCPTimeout.Duration())
	}
	if cfg.Detection.Beacon.MinSessions != 10 {
		t.Errorf("detection.beacon.min_sessions: got %d, want 10", cfg.Detection.Beacon.MinSessions)
	}
	if cfg.Detection.Beacon.MaxJitterRatio != 0.2 {
		t.Errorf("detection.beacon.max_jitter_ratio: got %f, want 0.2", cfg.Detection.Beacon.MaxJitterRatio)
	}
	if cfg.Detection.Beacon.MinDuration.Duration() != 2*time.Hour {
		t.Errorf("detection.beacon.min_duration: got %v, want 2h", cfg.Detection.Beacon.MinDuration.Duration())
	}
	if cfg.API.ListenAddr != ":8080" {
		t.Errorf("api.listen_addr: got %q, want %q", cfg.API.ListenAddr, ":8080")
	}
}

func TestLoad_MissingInterface(t *testing.T) {
	content := `
[capture]
snap_len = 65535

[api]
listen_addr = ":8080"

[pcap_buffer]
max_size_mb = 1024
`
	_, err := loadFromStringRaw(content)
	if err == nil {
		t.Fatal("expected validation error for missing capture.interface")
	}
	t.Logf("got expected error: %v", err)
}

func TestLoad_MissingListenAddr(t *testing.T) {
	content := `
[capture]
interface = "eth0"

[api]
listen_addr = ""

[pcap_buffer]
max_size_mb = 1024
`
	_, err := loadFromStringRaw(content)
	if err == nil {
		t.Fatal("expected validation error for empty api.listen_addr")
	}
	t.Logf("got expected error: %v", err)
}

func TestLoad_InvalidJitterRatio(t *testing.T) {
	content := `
[capture]
interface = "eth0"

[detection.beacon]
min_sessions     = 10
max_jitter_ratio = 1.5

[api]
listen_addr = ":8080"

[pcap_buffer]
max_size_mb = 1024
`
	_, err := loadFromStringRaw(content)
	if err == nil {
		t.Fatal("expected validation error for jitter_ratio > 1.0")
	}
	t.Logf("got expected error: %v", err)
}

func TestLoad_InvalidPcapSize(t *testing.T) {
	content := `
[capture]
interface = "eth0"

[api]
listen_addr = ":8080"

[pcap_buffer]
max_size_mb = 0
`
	_, err := loadFromStringRaw(content)
	if err == nil {
		t.Fatal("expected validation error for pcap_buffer.max_size_mb = 0")
	}
	t.Logf("got expected error: %v", err)
}

func TestLoad_DefaultValues(t *testing.T) {
	// Minimal config — everything else should be defaults.
	content := `
[capture]
interface = "eth0"

[api]
listen_addr = ":9090"

[pcap_buffer]
max_size_mb = 512
`
	cfg := loadFromString(t, content)

	// Check defaults were applied
	if cfg.Capture.Promisc != true {
		t.Errorf("capture.promiscuous default: got %v, want true", cfg.Capture.Promisc)
	}
	if cfg.Export.BatchSize != 500 {
		t.Errorf("export.batch_size default: got %d, want 500", cfg.Export.BatchSize)
	}
	if cfg.Export.FlushInterval.Duration() != 5*time.Second {
		t.Errorf("export.flush_interval default: got %v, want 5s", cfg.Export.FlushInterval.Duration())
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("logging.level default: got %q, want %q", cfg.Logging.Level, "info")
	}
	if cfg.Detection.DNSTunnel.EntropyThreshold != 3.5 {
		t.Errorf("detection.dns_tunnel.entropy_threshold default: got %f, want 3.5", cfg.Detection.DNSTunnel.EntropyThreshold)
	}
	if cfg.PcapBuffer.MaxFlowPackets != 50 {
		t.Errorf("pcap_buffer.max_flow_packets default: got %d, want 50", cfg.PcapBuffer.MaxFlowPackets)
	}
}

func TestLoad_OverrideDefaults(t *testing.T) {
	content := `
[capture]
interface = "eth0"
snap_len  = 1500
promiscuous = false

[detection.beacon]
min_sessions     = 20
max_jitter_ratio = 0.1
min_duration     = "4h"

[export]
batch_size     = 1000
flush_interval = "10s"

[api]
listen_addr = ":9090"

[pcap_buffer]
max_size_mb = 2048

[logging]
level  = "debug"
format = "console"
`
	cfg := loadFromString(t, content)

	if cfg.Capture.SnapLen != 1500 {
		t.Errorf("snap_len override: got %d, want 1500", cfg.Capture.SnapLen)
	}
	if cfg.Capture.Promisc != false {
		t.Errorf("promiscuous override: got %v, want false", cfg.Capture.Promisc)
	}
	if cfg.Detection.Beacon.MinSessions != 20 {
		t.Errorf("beacon.min_sessions override: got %d, want 20", cfg.Detection.Beacon.MinSessions)
	}
	if cfg.Export.BatchSize != 1000 {
		t.Errorf("export.batch_size override: got %d, want 1000", cfg.Export.BatchSize)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("logging.level override: got %q, want %q", cfg.Logging.Level, "debug")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func loadFromString(t *testing.T, content string) *Config {
	t.Helper()
	cfg, err := loadFromStringRaw(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return cfg
}

func loadFromStringRaw(content string) (*Config, error) {
	dir, err := os.MkdirTemp("", "akeso-config-test")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "test.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return nil, err
	}
	return Load(path)
}
