# Multi-arch build guide

## Local build (current host architecture)

```bash
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.arm64 .
```

## Multi-arch build (requires buildx + registry push)

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<user>/urban-hack-sentinel:latest \
  -f docker/Dockerfile.arm64 . \
  --push
```

Notes:
- Keep `docker/Dockerfile.arm64` as the canonical multi-arch input; `docker/Dockerfile.amd64` exists as an x86_64-specific overlay/runtime reference.
- When `TARGETARCH` is provided by buildx, the runtime stage will select the correct package set automatically.
- For local qemu-based cross builds, enable `docker buildx create --use` and install `qemu-user-static` on the builder host.
