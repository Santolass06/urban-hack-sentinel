# Guia de Build Multi-arquitectura

## Build local (arquitectura atual do anfitrião)

```bash
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.arm64 .
```

## Builds por arquitectura específica

```bash
# ARM64 (Raspberry Pi)
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.arm64 .

# AMD64 / x86_64
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.amd64 .
```

## Multi-arch build + push (requer buildx + registry)

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<user>/urban-hack-sentinel:latest \
  --push
```

## Execução

```bash
# ARM64
docker run --rm --network=host urban-hack-sentinel:latest urban-hs info

# x86_64
docker run --rm --platform linux/amd64 --network=host urban-hack-sentinel:latest urban-hs info
```

## Notas

- Mantenha `docker/Dockerfile.arm64` como entrada multi-arquitectura canónica.
- `docker/Dockerfile.amd64` é a sobreposição/ referência de runtime específica para x86_64.
- Quando `TARGETARCH` é fornecido pelo buildx, o estágio de runtime seleciona o conjunto de pacotes correto automaticamente.
- Para builds cruzados locais com QEMU, ative `docker buildx create --use` e instale `qemu-user-static` no anfitrião de build.

## Resolução de problemas

- **`exec format error`** — está a tentar executar uma imagem ARM64 num anfitrião x86_64 sem QEMU. Use `--platform` ou build para a arquitectura do seu anfitrião.
- **Falta de memória durante o build** — aumente a memória do Docker ou use `--no-cache` com uma imagem base mais pequena.
- **Permission denied em `/dev/net/tun`** — execute o contentor com `--privileged` ou adicione a capacidade `NET_ADMIN`.
