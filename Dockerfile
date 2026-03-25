# =============================================================================
# AkesoNDR Sensor — Multi-stage Docker build
# =============================================================================

# --- Stage 1: Build ---
FROM golang:1.24-bookworm AS builder

ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -v \
    -ldflags "-X main.version=$(date +%Y%m%d)-docker" \
    -o /usr/local/bin/akeso-ndr ./cmd/akeso-ndr

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/akeso-ndr /usr/local/bin/akeso-ndr

# Default data directories
RUN mkdir -p /var/lib/akeso-ndr/pcap /etc/akeso-ndr

ENTRYPOINT ["akeso-ndr"]
CMD ["--interface", "eth0"]
