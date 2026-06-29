# Urban Hack Sentinel - Multi-arch Dockerfile
# Build: docker buildx build --platform linux/arm64,linux/amd64 -t ghcr.io/<owner>/urban-hack-sentinel:latest --push .

# ============================================================
# Build Stage
# ============================================================
FROM --platform=$BUILDPLATFORM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    libbluetooth-dev \
    libgpgme-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -e ".[dev]"

# ============================================================
# Runtime Stage
# ============================================================
FROM --platform=$TARGETPLATFORM python:3.11-slim AS runtime

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    aircrack-ng \
    hcxtools \
    reaver \
    bully \
    macchanger \
    iw \
    jq \
    bluez \
    bluez-tools \
    gpsd \
    gpsd-clients \
    nmap \
    nuclei \
    metasploit-framework \
    hashcat \
    libgpgme-dev \
    libbluetooth-dev \
    libpcap-dev \
    libcap2-bin \
    iproute2 \
    wireless-tools \
    net-tools \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r urbanhs && useradd -r -g urbanhs -m -d /home/urbanhs -s /bin/bash urbanhs

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application
COPY src/ /app/src/
COPY scripts/ /app/scripts/
COPY config.env.example /app/config.env.example

# Create directories
RUN mkdir -p /var/lib/urban-hs/hashes /var/lib/urban-hs/pcaps /var/lib/urban-hs/artifacts /var/log/urban-hs/jsonl \
    && chown -R urbanhs:urbanhs /var/lib/urban-hs /var/log/urban-hs

# Set capabilities for network tools (non-root execution)
RUN setcap 'cap_net_admin,cap_net_raw+ep' $(which airodump-ng) 2>/dev/null || true && \
    setcap 'cap_net_admin,cap_net_raw+ep' $(which aireplay-ng) 2>/dev/null || true && \
    setcap 'cap_net_admin,cap_net_raw+ep' $(which aircrack-ng) 2>/dev/null || true && \
    setcap 'cap_net_admin,cap_net_raw+ep' $(which hcxdumptool) 2>/dev/null || true && \
    setcap 'cap_net_admin,cap_net_raw+ep' $(which hcxpcapngtool) 2>/dev/null || true && \
    setcap 'cap_net_admin,cap_net_raw+ep' $(which nmap) 2>/dev/null || true && \
    setcap 'cap_net_admin,cap_net_raw+ep' $(which nuclei) 2>/dev/null || true && \
    setcap 'cap_net_admin,cap_net_raw+ep' $(which msfconsole) 2>/dev/null || true

# Switch to non-root user
USER urbanhs

WORKDIR /app

# Default command
CMD ["python", "-m", "urban_hs.cli.main", "--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import sys; sys.path.insert(0, '/app/src'); from urban_hs.core.health import create_health_checker; import asyncio; hc = create_health_checker(); result = asyncio.run(hc.check()) ; exit(0 if result.healthy else 1)"