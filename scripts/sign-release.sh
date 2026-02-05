#!/usr/bin/env bash
# =============================================================================
# JoinMarket NG Release Signing Script
#
# This script helps trusted parties sign release manifests.
#
# Usage:
#   ./scripts/sign-release.sh <version> [--key <fingerprint>]
#   ./scripts/sign-release.sh --key <fingerprint>  # Auto-detect latest unsigned
#
# Requirements:
#   - gpg (GnuPG) with a valid signing key
#   - curl or wget
#   - git
#   - gh (GitHub CLI) for auto-detection
#   - docker with buildx (for --reproduce)
#   - jq (for --reproduce digest extraction)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPO="m0wer/joinmarket-ng"  # Update this with your actual repo
REGISTRY="ghcr.io"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
Usage: $(basename "$0") [version] [options]

Sign a JoinMarket NG release manifest.

Arguments:
  version         Release version to sign (e.g., 1.0.0)
                  If omitted, auto-detects latest unsigned release for your key

Options:
  --key KEY       GPG key fingerprint to use for signing (required for auto-detect)
  --reproduce     Build locally and verify digests match before signing (recommended)
  --no-reproduce  Skip local build verification (not recommended)
  --no-push       Don't automatically commit and push the signature (default: push)
  --help          Show this help message

All signers should use --reproduce to independently verify that builds are reproducible
before signing. Multiple signatures only add value if each signer verifies independently.
By default, --reproduce is enabled unless --no-reproduce is specified.

Examples:
  $(basename "$0") 1.0.0 --key ABCD1234...              # Verify and sign
  $(basename "$0") 1.0.0 --key ABCD1234... --no-reproduce  # Sign without verify (not recommended)
  $(basename "$0") --key ABCD1234...                    # Auto-detect latest unsigned
  $(basename "$0") 1.0.0 --key ABCD1234... --no-push
EOF
    exit 1
}

# Parse arguments
VERSION=""
GPG_KEY=""
REPRODUCE=true  # Default to true - all signers should verify
AUTO_PUSH=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --key)
            GPG_KEY="$2"
            shift 2
            ;;
        --reproduce)
            REPRODUCE=true
            shift
            ;;
        --no-reproduce)
            REPRODUCE=false
            shift
            ;;
        --no-push)
            AUTO_PUSH=false
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
            else
                log_error "Unknown argument: $1"
                usage
            fi
            shift
            ;;
    esac
done

# =============================================================================
# Step 0: Get GPG key early (needed for auto-detection)
# =============================================================================
if [[ -z "$GPG_KEY" ]]; then
    log_info "Available GPG secret keys:"
    gpg --list-secret-keys --keyid-format LONG
    echo ""
    read -p "Enter GPG key fingerprint to use: " GPG_KEY
fi

# Get full fingerprint
FULL_FINGERPRINT=$(gpg --fingerprint "$GPG_KEY" 2>/dev/null | \
                   grep -oP '[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}' | \
                   tr -d ' ' | head -1)

if [[ -z "$FULL_FINGERPRINT" ]]; then
    log_error "Could not find GPG key: $GPG_KEY"
    exit 1
fi

log_info "Using GPG key: $FULL_FINGERPRINT"

# =============================================================================
# Step 0.5: Auto-detect latest unsigned release if version not specified
# =============================================================================
if [[ -z "$VERSION" ]]; then
    log_info "No version specified, auto-detecting latest unsigned release..."

    if ! command -v gh &> /dev/null; then
        log_error "GitHub CLI (gh) is required for auto-detection. Please install it or specify a version."
        exit 1
    fi

    # Get all releases sorted by date (newest first)
    RELEASES=$(gh release list --repo "$REPO" --limit 20 | awk '{print $1}')

    if [[ -z "$RELEASES" ]]; then
        log_error "No releases found in repository"
        exit 1
    fi

    # Find the first release without a signature from this key
    for release in $RELEASES; do
        # Check if signature file exists for this release
        SIG_PATH="$PROJECT_ROOT/signatures/$release/${FULL_FINGERPRINT}.sig"
        if [[ ! -f "$SIG_PATH" ]]; then
            VERSION="$release"
            log_info "Found unsigned release: $VERSION"
            break
        fi
    done

    if [[ -z "$VERSION" ]]; then
        log_info "All recent releases are already signed with your key!"
        exit 0
    fi
fi

# Create temp directory
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

log_info "Signing JoinMarket NG release $VERSION"

# =============================================================================
# Step 1: Download release manifest
# =============================================================================
log_info "Downloading release manifest..."

MANIFEST_URL="https://github.com/${REPO}/releases/download/${VERSION}/release-manifest-${VERSION}.txt"
MANIFEST_FILE="$WORK_DIR/release-manifest-${VERSION}.txt"

if command -v curl &> /dev/null; then
    curl -fsSL "$MANIFEST_URL" -o "$MANIFEST_FILE" || {
        log_error "Failed to download release manifest from $MANIFEST_URL"
        exit 1
    }
elif command -v wget &> /dev/null; then
    wget -q "$MANIFEST_URL" -O "$MANIFEST_FILE" || {
        log_error "Failed to download release manifest from $MANIFEST_URL"
        exit 1
    }
else
    log_error "Neither curl nor wget found. Please install one of them."
    exit 1
fi

log_info "Downloaded release manifest:"
echo ""
cat "$MANIFEST_FILE"
echo ""

# =============================================================================
# Step 2: Optionally reproduce builds (for first signer)
# =============================================================================
if [[ "$REPRODUCE" == true ]]; then
    # Check for jq (required for OCI manifest parsing)
    if ! command -v jq &> /dev/null; then
        log_error "jq is required for --reproduce. Please install it."
        exit 1
    fi

    # Detect current architecture
    detect_arch() {
        local arch
        arch=$(uname -m)
        case "$arch" in
            x86_64)  echo "amd64" ;;
            aarch64) echo "arm64" ;;
            armv7l)  echo "arm-v7" ;;
            *)       echo "$arch" ;;
        esac
    }

    CURRENT_ARCH=$(detect_arch)
    log_info "Reproducing builds for $CURRENT_ARCH to verify manifest digests..."

    # Map arch to Docker platform format
    case "$CURRENT_ARCH" in
        amd64)  PLATFORM="linux/amd64" ;;
        arm64)  PLATFORM="linux/arm64" ;;
        arm-v7) PLATFORM="linux/arm/v7" ;;
        *)
            log_error "Unsupported architecture: $CURRENT_ARCH"
            exit 1
            ;;
    esac

    # Extract commit and SOURCE_DATE_EPOCH from manifest
    COMMIT=$(grep "^commit:" "$MANIFEST_FILE" | cut -d' ' -f2)
    SOURCE_DATE_EPOCH=$(grep "^source_date_epoch:" "$MANIFEST_FILE" | cut -d' ' -f2)

    if [[ -z "$COMMIT" || -z "$SOURCE_DATE_EPOCH" ]]; then
        log_error "Could not extract commit or SOURCE_DATE_EPOCH from manifest"
        exit 1
    fi

    log_info "Commit: $COMMIT"
    log_info "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
    log_info "Platform: $PLATFORM"

    # Extract expected digests from manifest
    declare -A EXPECTED_DIGESTS
    while IFS=': ' read -r key value || [[ -n "$key" ]]; do
        [[ "$key" =~ ^#.*$ || -z "$value" ]] && continue
        [[ "$key" == "commit" || "$key" == "source_date_epoch" ]] && continue
        if [[ "$value" =~ ^sha256: ]]; then
            EXPECTED_DIGESTS["$key"]="$value"
        fi
    done < "$MANIFEST_FILE"

    # Clone repository at specific commit
    REPO_DIR="$WORK_DIR/repo"
    log_info "Cloning repository at commit $COMMIT..."
    git clone --depth 1 "https://github.com/${REPO}.git" "$REPO_DIR"
    cd "$REPO_DIR"
    git fetch --depth 1 origin "$COMMIT"
    git checkout "$COMMIT"

    # Build images for current architecture only
    IMAGES=("directory-server" "maker" "taker" "orderbook-watcher")
    DOCKERFILES=("./directory_server/Dockerfile" "./maker/Dockerfile" "./taker/Dockerfile" "./orderbook_watcher/Dockerfile")

    # Create OCI output directory
    OCI_DIR="$WORK_DIR/oci"
    mkdir -p "$OCI_DIR"

    REPRODUCE_ERRORS=0
    REPRODUCE_SUCCESS=0

    for i in "${!IMAGES[@]}"; do
        image="${IMAGES[$i]}"
        dockerfile="${DOCKERFILES[$i]}"
        digest_key="${image}-${CURRENT_ARCH}"

        # Check for per-platform digest (new format) or fall back to old format
        if [[ -v "EXPECTED_DIGESTS[$digest_key]" ]]; then
            expected="${EXPECTED_DIGESTS[$digest_key]}"
        else
            log_warn "No per-platform digest for $digest_key in manifest"
            log_warn "Manifest may be old format - skipping reproduce for $image"
            continue
        fi

        log_info "Building $image for $PLATFORM..."

        # Build to OCI tar format (no local registry needed)
        # Use rewrite-timestamp=true to clamp all file timestamps to SOURCE_DATE_EPOCH
        # Use --no-cache to ensure a clean build matching CI
        OCI_TAR="$OCI_DIR/${image}.tar"
        OCI_EXTRACT="$OCI_DIR/${image}"
        mkdir -p "$OCI_EXTRACT"

        if ! SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" docker buildx build \
            --file "$dockerfile" \
            --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
            --build-arg VERSION="$VERSION" \
            --platform "$PLATFORM" \
            --output "type=oci,dest=${OCI_TAR},rewrite-timestamp=true" \
            --no-cache \
            . 2>&1 | tee "$WORK_DIR/${image}-build.log"; then
            log_error "  Build failed for $image"
            REPRODUCE_ERRORS=$((REPRODUCE_ERRORS + 1))
            continue
        fi

        # Extract OCI tar and get manifest digest
        tar -xf "$OCI_TAR" -C "$OCI_EXTRACT"

        # Get the manifest digest from OCI index.json
        # For single-platform builds, index.json points to the image manifest
        built_digest=$(jq -r '.manifests[0].digest' "$OCI_EXTRACT/index.json")

        if [[ "$built_digest" == "$expected" ]]; then
            log_info "  Digest matches: $expected"
            REPRODUCE_SUCCESS=$((REPRODUCE_SUCCESS + 1))
        else
            log_error "  Digest mismatch!"
            log_error "    Expected: $expected"
            log_error "    Built:    $built_digest"
            REPRODUCE_ERRORS=$((REPRODUCE_ERRORS + 1))
        fi

        # Clean up OCI files
        rm -rf "$OCI_TAR" "$OCI_EXTRACT"
    done

    cd "$PROJECT_ROOT"

    echo ""
    log_info "Reproducibility Summary: $REPRODUCE_SUCCESS succeeded, $REPRODUCE_ERRORS failed"

    if [[ $REPRODUCE_ERRORS -gt 0 ]]; then
        log_error "Cannot sign: builds do not reproduce!"
        log_error "The locally built images have different digests than the manifest."
        log_error "Possible causes:"
        log_error "  - Different BuildKit version than CI"
        log_error "  - Platform differences"
        log_error "  - Non-deterministic build steps"
        exit 1
    fi

    log_info "All builds reproduced successfully!"
    echo ""
fi

# =============================================================================
# Step 3: Get GPG key (already done above for auto-detection)
# =============================================================================
log_info "Using GPG key: $FULL_FINGERPRINT"

# =============================================================================
# Step 4: Sign the manifest
# =============================================================================
log_info "Signing release manifest..."

SIG_DIR="$PROJECT_ROOT/signatures/$VERSION"
mkdir -p "$SIG_DIR"

SIG_FILE="$SIG_DIR/${FULL_FINGERPRINT}.sig"

gpg --local-user "$GPG_KEY" --armor --detach-sign --output "$SIG_FILE" "$MANIFEST_FILE"

log_info "Signature created: $SIG_FILE"

# =============================================================================
# Step 5: Verify the signature
# =============================================================================
log_info "Verifying signature..."

if gpg --verify "$SIG_FILE" "$MANIFEST_FILE"; then
    log_info "Signature verified successfully!"
else
    log_error "Signature verification failed!"
    rm -f "$SIG_FILE"
    exit 1
fi

# =============================================================================
# Summary and next steps
# =============================================================================
echo ""
echo "=============================================="
log_info "Signing Complete!"
echo "=============================================="
echo ""
echo "Signature file: $SIG_FILE"
echo ""

# Check if key is in trusted-keys.txt
TRUSTED_KEYS="$PROJECT_ROOT/signatures/trusted-keys.txt"
if ! grep -q "$FULL_FINGERPRINT" "$TRUSTED_KEYS" 2>/dev/null; then
    log_warn "Your key is not in trusted-keys.txt"
    echo "To be included in automated verification, add your key:"
    echo ""
    echo "  echo '$FULL_FINGERPRINT Your Name' >> signatures/trusted-keys.txt"
    echo ""
fi

# =============================================================================
# Step 6: Auto commit and push (unless --no-push)
# =============================================================================
if [[ "$AUTO_PUSH" == true ]]; then
    log_info "Committing and pushing signature..."

    cd "$PROJECT_ROOT"
    git add "$SIG_FILE"
    git commit -m "build: add GPG signature for release $VERSION"
    git push

    log_info "Signature committed and pushed successfully!"
else
    echo "Next steps:"
    echo "1. Review the signature file"
    echo "2. Commit and push your signature:"
    echo "   git add $SIG_FILE"
    echo "   git commit -m 'build: add GPG signature for release $VERSION'"
    echo "   git push"
    echo ""
    echo "3. Or create a PR with your signature if you don't have write access"
    echo ""
fi
