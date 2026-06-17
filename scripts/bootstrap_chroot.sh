#!/bin/bash
#
# Alpine Chroot Bootstrap for Urban Hack Sentinel
# Creates a minimal Alpine Linux chroot with security tools pre-installed.
# Run as root: sudo ./bootstrap_chroot.sh

set -euo pipefail

# Configuration
CHROOT_DIR="/opt/urban-hs/chroot/alpine"
ALPINE_VERSION="3.20"
ALPINE_ARCH="aarch64"
MIRROR="https://dl-cdn.alpinelinux.org/alpine"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Check if chroot already exists
if [[ -d "$CHROOT_DIR" ]]; then
    log_warn "Chroot directory $CHROOT_DIR already exists"
    read -p "Remove and recreate? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Aborted"
        exit 0
    fi
    rm -rf "$CHROOT_DIR"
fi

log_info "Creating Alpine chroot at $CHROOT_DIR"

# Create directory structure
mkdir -p "$CHROOT_DIR"

# Download Alpine minirootfs
MINIROOTFS="alpine-minirootfs-${ALPINE_VERSION}-${ALPINE_ARCH}.tar.gz"
MINIROOTFS_URL="${MIRROR}/v${ALPINE_VERSION%.*}/releases/${ALPINE_ARCH}/${MINIROOTFS}"
SHA256_URL="${MINIROOTFS_URL}.sha256"

log_info "Downloading Alpine minirootfs..."
cd /tmp
if [[ ! -f "$MINIROOTFS" ]]; then
    wget -q "$MINIROOTFS_URL" -O "$MINIROOTFS"
fi

# Verify checksum
log_info "Verifying checksum..."
if [[ ! -f "$MINIROOTFS.sha256" ]]; then
    wget -q "$SHA256_URL" -O "$MINIROOTFS.sha256"
fi
sha256sum -c "$MINIROOTFS.sha256" || {
    log_error "Checksum verification failed!"
    exit 1
}

log_info "Extracting minirootfs..."
tar -xzf "$MINIROOTFS" -C "$CHROOT_DIR"

# Configure DNS
cp /etc/resolv.conf "$CHROOT_DIR/etc/resolv.conf"

# Bind mount essential filesystems
log_info "Setting up bind mounts..."
mount -t proc /proc "$CHROOT_DIR/proc" 2>/dev/null || true
mount -t sysfs /sys "$CHROOT_DIR/sys" 2>/dev/null || true
mount -o bind /dev "$CHROOT_DIR/dev" 2>/dev/null || true
mount -o bind /dev/pts "$CHROOT_DIR/dev/pts" 2>/dev/null || true
mount -o bind /run "$CHROOT_DIR/run" 2>/dev/null || true

# Create data/artifacts/logs directories in host and bind mount
mkdir -p /var/lib/urban-hs/{data,artifacts,logs,hashes,pcaps}
mkdir -p "$CHROOT_DIR/data" "$CHROOT_DIR/artifacts" "$CHROOT_DIR/logs"

mount -o bind /var/lib/urban-hs/data "$CHROOT_DIR/data"
mount -o bind /var/lib/urban-hs/artifacts "$CHROOT_DIR/artifacts"
mount -o bind /var/lib/urban-hs/logs "$CHROOT_DIR/logs"

# Configure Alpine repositories - use only stable repos for security
cat > "$CHROOT_DIR/etc/apk/repositories" <<EOF
${MIRROR}/v${ALPINE_VERSION%.*}/main
${MIRROR}/v${ALPINE_VERSION%.*}/community
EOF

# Update and install base packages
log_info "Updating package index..."
chroot "$CHROOT_DIR" apk update

log_info "Installing base system packages..."
chroot "$CHROOT_DIR" apk add --no-cache \
    bash \
    coreutils \
    findutils \
    grep \
    sed \
    awk \
    curl \
    wget \
    tar \
    gzip \
    bzip2 \
    xz \
    unzip \
    p7zip \
    git \
    openssh-client \
    openssl \
    ca-certificates \
    sudo \
    shadow \
    util-linux \
    e2fsprogs \
    dosfstools \
    ntfs-3g \
    htop \
    iotop \
    iftop \
    nethogs \
    strace \
    lsof \
    tcpdump \
    iproute2 \
    iputils \
    net-tools \
    bridge-utils \
    wireless-tools \
    iw \
    ethtool \
    usbutils \
    pciutils \
    lsblk \
    smartmontools \
    dmidecode \
    lm_sensors \
    hwloc \
    numactl \
    python3 \
    py3-pip \
    py3-setuptools \
    py3-wheel \
    py3-virtualenv \
    py3-yaml \
    py3-requests \
    py3-aiohttp \
    py3-asyncpg \
    py3-redis \
    py3-sqlalchemy \
    py3-cryptography \
    py3-paramiko \
    py3-scapy \
    py3-nmap \
    py3-netifaces \
    py3-bleak \
    py3-dbus \
    py3-gobject \
    py3-cairo \
    py3-pillow \
    py3-lxml \
    py3-jinja2 \
    py3-weasyprint \
    py3-markdown \
    py3-pygments \
    py3-rich \
    py3-textual \
    py3-click \
    py3-typer \
    py3-pytest \
    py3-pytest-asyncio \
    py3-mock \
    nodejs \
    npm \
    ruby \
    ruby-bundler \
    perl \
    lua5.4 \
    go \
    rust \
    cargo \
    gcc \
    g++ \
    make \
    cmake \
    meson \
    ninja \
    pkgconf \
    linux-headers \
    musl-dev \
    openssl-dev \
    libffi-dev \
    zlib-dev \
    bzip2-dev \
    readline-dev \
    sqlite-dev \
    postgresql-dev \
    mariadb-dev \
    libxml2-dev \
    libxslt-dev \
    libpcap-dev \
    libnl3-dev \
    libusb-dev \
    bluez-dev \
    bluez-tools \
    bluez-deprecated \
    ofono \
    ofono-dbus \
    bluealsa \
    bluez-hcidump \
    gpsd \
    gpsd-clients \
    chrony \
    ntpsec \
    wireguard-tools \
    openvpn \
    strongswan \
    ipsec-tools \
    openswan \
    ipvsadm \
    keepalived \
    haproxy \
    nginx \
    apache2 \
    lighttpd \
    caddy \
    traefik \
    squid \
    polipo \
    tinyproxy \
    privoxy \
    tor \
    i2pd \
    kovri \
    sos \
    sysstat \
    dstat \
    atop \
    glances \
    bmon \
    nload \
    vnstat \
    iftop \
    nethogs \
    bwm-ng \
    darkstat \
    ntopng \
    argus \
    argus-clients \
    ra \
    silk \
    yaf \
    nfdump \
    nfsen \
    pmacct \
    flow-tools \
    softflowd \
    fprobe \
    ipfixprobe \
    nfcapd \
    nfpcapd \
    nfreplay \
    nfdump \
    nfexpire \
    nfanon \
    nfpcapd \
    nfreplay \
    nfdump \
    nfexpire \
    nfanon

log_info "Cleaning up..."
chroot "$CHROOT_DIR" apk cache clean
rm -rf "$CHROOT_DIR/var/cache/apk/*"
rm -rf "$CHROOT_DIR/tmp/*"
rm -rf "$CHROOT_DIR/var/tmp/*"

log_info "Chroot bootstrap completed successfully!"
log_info "Chroot location: $CHROOT_DIR"
log_info ""
log_info "To enter chroot:"
log_info "  sudo chroot $CHROOT_DIR /bin/bash"
log_info ""
log_info "To run commands in chroot from host:"
log_info "  sudo chroot $CHROOT_DIR /bin/bash -c 'command'"
log_info ""
log_info "Bind mounts configured:"
log_info "  /var/lib/urban-hs/data -> $CHROOT_DIR/data"
log_info "  /var/lib/urban-hs/artifacts -> $CHROOT_DIR/artifacts"
log_info "  /var/lib/urban-hs/logs -> $CHROOT_DIR/logs"