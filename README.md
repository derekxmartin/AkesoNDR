# AkesoNDR

A Go proof of concept for learning network detection and response. It parses packet captures, tracks sessions, and explores protocol metadata, detection heuristics, signatures, and security-event export.

The current command-line entry point connects capture, session tracking, and protocol parsing. Detection, export, and API packages also exist, but their presence does not establish a complete running detection-and-response service. This is an experimental lab project.

## Architecture

| Area | Source | Role |
|---|---|---|
| Capture and reassembly | `internal/capture/` | Live interfaces and offline PCAP input |
| Sessions and protocols | `internal/sessions/`, `internal/protocols/` | Connection tracking and protocol metadata |
| Detection and signatures | `internal/detect/`, `internal/signatures/` | Independently tested detection components |
| API and export | `internal/api/`, `internal/export/` | API and ECS export components |
| CLI | `cmd/akeso-ndr/` | Capture, parsing, and session-log orchestration |

## Build and test

Use Go 1.26 and a C compiler with libpcap development headers. On Ubuntu, install `libpcap-dev`; other platforms require the appropriate packet-capture development library.

```sh
go build -o bin/akeso-ndr ./cmd/akeso-ndr
go vet ./...
go test -race ./...
```

## Reproducible local walkthrough

The checked-in integration tests use a fixture PCAP and synthetic HTTP messages:

```sh
go test -v ./tests/integration -run 'TestDNSFromPCAP|TestHTTPFromSynthetic|TestRouterStatsFromPCAP'
```

Successful checks verify DNS metadata from the fixture, a synthetic `GET /index.html` response, and nonzero DNS classification counts. No live network capture or target credentials are needed.

To inspect the fixture through the CLI:

```sh
./bin/akeso-ndr -pcap tests/pcaps/test.pcap
```

The program logs extracted metadata and waits for a shutdown signal even after the capture is consumed. Press Ctrl+C to request shutdown and print its summary. Use captures you own or have permission to inspect; captured traffic can contain sensitive data.

## Validation limits

CI builds the code and runs vet plus race-enabled tests. Protocol and component tests do not demonstrate sustained sensor throughput, complete encrypted-traffic visibility, inline prevention, or a fully connected SIEM deployment. The roadmap in `REQUIREMENTS.md` should be read separately from implemented CLI behavior.

## Licensing and contributions

No project-wide license has been selected for the original code. Public visibility does not grant a general reuse or redistribution license; contact the repository owner about intended use. Dependencies retain their own licenses. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
