# Multi-architecture Build Guide

## Local build (current host architecture)

```bash
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.arm64 .
```

## Architecture-specific builds

```bash
# ARM64 (Raspberry Pi)
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.arm64 .

# AMD64 / x86_64
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.amd64 .
```

## Multi-arch build + push (requires buildx + registry)

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<user>/urban-hack-sentinel:latest \
  --push
```

## Running

```bash
# ARM64
docker run --rm --network=host urban-hack-sentinel:latest urban-hs info

# x86_64
docker run --rm --platform linux/amd64 --network=host urban-hack-sentinel:latest urban-hs info
```

## Notes

- Keep `docker/Dockerfile.arm64` as the canonical multi-arch input.
- `docker/Dockerfile.amd64` is the x86_64-specific overlay/runtime reference.
- When `TARGETARCH` is provided by buildx, the runtime stage selects the correct package set automatically.
- For local QEMU-based cross builds, enable `docker buildx create --use` and install `qemu-user-static` on the builder host.

## Troubleshooting

- **`exec format error`** — you are trying to run an ARM64 image on an x86_64 host without QEMU. Use `--platform` or build for your host architecture.
- **Out of memory during build** — increase Docker memory or use `--no-cache` with a smaller base image.
- **Permission denied on `/dev/net/tun`** — run the container with `--privileged` or add the `NET_ADMIN` capability.
