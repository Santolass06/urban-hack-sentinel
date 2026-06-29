#!/usr/bin/env bash
set -euo pipefail

# Urban Hack Sentinel - Release Automation Script
# Usage: ./scripts/release.sh <version>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v3.0.0"
    exit 1
fi

# Validate version format
if ! [[ "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9\.-]+)?$ ]]; then
    echo "Invalid version format. Use semantic versioning (e.g., v3.0.0 or 3.0.0)"
    exit 1
fi

# Ensure version starts with 'v'
if [[ ! "$VERSION" =~ ^v ]]; then
    VERSION="v$VERSION"
fi

echo "=== Urban Hack Sentinel Release $VERSION ==="

cd "$PROJECT_ROOT"

# 1. Update version in pyproject.toml
echo "Updating pyproject.toml version..."
sed -i "s/version = \".*\"/version = \"${VERSION#v}\"/" pyproject.toml

# 2. Update version in src/urban_hs/__init__.py if it exists
if [[ -f "src/urban_hs/__init__.py" ]]; then
    sed -i "s/__version__ = \".*\"/__version__ = \"${VERSION#v}\"/" src/urban_hs/__init__.py
fi

# 3. Generate changelog
echo "Generating changelog..."
git log --oneline --pretty=format:"- %s (%h)" $(git describe --tags --abbrev=0 2>/dev/null || echo "")..HEAD > CHANGELOG.md.tmp
echo "# Changelog for $VERSION" > CHANGELOG.md
cat CHANGELOG.md.tmp >> CHANGELOG.md
rm CHANGELOG.md.tmp

# 4. Run tests
echo "Running tests..."
python -m pytest tests/ -v --tb=short -x

# 5. Build Docker images (multi-arch)
echo "Building Docker images..."
docker buildx create --name urban-hs-builder --use 2>/dev/null || true
docker buildx build \
    --platform linux/arm64,linux/amd64 \
    -t ghcr.io/<owner>/urban-hack-sentinel:${VERSION} \
    -t ghcr.io/<owner>/urban-hack-sentinel:latest \
    --push \
    -f docker/Dockerfile.arm64 \
    .

# 6. Generate SBOM with Syft
echo "Generating SBOM with Syft..."
syft packages dir:. -o spdx-json=sbom-${VERSION}.spdx.json
syft packages dir:. -o cyclonedx-json=sbom-${VERSION}.cdx.json

# 7. Sign artifacts with Cosign
echo "Signing artifacts with Cosign..."
cosign sign-blob --key env://COSIGN_PRIVATE_KEY --output-signature urban-hs-${VERSION}.sig sbom-${VERSION}.spdx.json
cosign sign-blob --key env://COSIGN_PRIVATE_KEY --output-signature urban-hs-${VERSION}.cdx.sig sbom-${VERSION}.cdx.json

# 6. Create GitHub release
echo "Creating GitHub release..."
gh release create "${VERSION}" \
    --title "Urban Hack Sentinel ${VERSION}" \
    --notes-file CHANGELOG.md \
    --generate-notes

echo "=== Release ${VERSION} completed successfully! ==="