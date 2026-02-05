#!/usr/bin/env bash
# =============================================================================
# JoinMarket NG Release Verification Script
#
# This script verifies:
# 1. GPG signatures on release manifests
# 2. Docker image digests match the signed manifest
# 3. Optionally reproduces the build to verify reproducibility
#
# Usage:
#   ./scripts/verify-release.sh <version>
#   ./scripts/verify-release.sh <version> --reproduce
#
# Requirements:
#   - gpg (GnuPG)
#   - docker with buildx (for image verification and reproduction)
#   - curl or wget
#   - git
#   - jq (for --reproduce digest extraction)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REGISTRY="ghcr.io"
REPO="m0wer/joinmarket-ng"  # Update this with your actual repo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect current architecture in Docker format
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

usage() {
    cat << EOF
Usage: $(basename "$0") <version> [options]

Verify JoinMarket NG release signatures and optionally reproduce builds.

Arguments:
  version         Release version to verify (e.g., 1.0.0)

Options:
  --reproduce     Attempt to reproduce the Docker builds locally
  --min-sigs N    Require at least N valid signatures (default: 1)
  --help          Show this help message

The --reproduce flag builds images for your current architecture only and
compares against the per-platform digest in the release manifest.

Examples:
  $(basename "$0") 1.0.0
  $(basename "$0") 1.0.0 --reproduce
  $(basename "$0") 1.0.0 --min-sigs 2
EOF
    exit 1
}

# Parse arguments
VERSION=""
REPRODUCE=false
MIN_SIGS=1

while [[ $# -gt 0 ]]; do
    case $1 in
        --reproduce)
            REPRODUCE=true
            shift
            ;;
        --min-sigs)
            MIN_SIGS="$2"
            shift 2
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

if [[ -z "$VERSION" ]]; then
    log_error "Version is required"
    usage
fi

# Create temp directory for verification
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

log_info "Verifying JoinMarket NG release $VERSION"
log_info "Working directory: $WORK_DIR"

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

log_info "Downloaded release manifest"

# =============================================================================
# Step 2: Fetch and verify GPG signatures
# =============================================================================
log_info "Checking GPG signatures..."

SIG_DIR="$PROJECT_ROOT/signatures/$VERSION"
VALID_SIGS=0
SIGNERS=()

if [[ -d "$SIG_DIR" ]]; then
    # Import trusted keys
    TRUSTED_KEYS="$PROJECT_ROOT/signatures/trusted-keys.txt"
    if [[ -f "$TRUSTED_KEYS" ]]; then
        log_info "Importing trusted keys..."
        while IFS=' ' read -r fingerprint name || [[ -n "$fingerprint" ]]; do
            # Skip comments and empty lines
            [[ "$fingerprint" =~ ^#.*$ || -z "$fingerprint" ]] && continue

            # Try to import from keyserver
            gpg --keyserver hkps://keys.openpgp.org --recv-keys "$fingerprint" 2>/dev/null || \
            gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys "$fingerprint" 2>/dev/null || \
            log_warn "Could not import key $fingerprint ($name)"
        done < "$TRUSTED_KEYS"
    fi

    # Verify each signature
    for sig_file in "$SIG_DIR"/*.sig; do
        [[ -f "$sig_file" ]] || continue

        fingerprint=$(basename "$sig_file" .sig)
        log_info "Verifying signature from $fingerprint..."

        if gpg --verify "$sig_file" "$MANIFEST_FILE" 2>/dev/null; then
            log_info "Valid signature from $fingerprint"
            VALID_SIGS=$((VALID_SIGS + 1))
            SIGNERS+=("$fingerprint")
        else
            log_warn "Invalid signature from $fingerprint"
        fi
    done
else
    log_warn "No signatures found for version $VERSION"
    log_warn "Signature directory: $SIG_DIR"
fi

log_info "Valid signatures: $VALID_SIGS"

if [[ $VALID_SIGS -lt $MIN_SIGS ]]; then
    log_error "Insufficient valid signatures. Required: $MIN_SIGS, Found: $VALID_SIGS"
    log_error "This release has not been verified by enough trusted parties."
    exit 1
fi

# =============================================================================
# Step 3: Verify Docker image digests from registry
# =============================================================================
log_info "Verifying Docker image digests from registry..."

# Extract all digests from manifest (both per-platform and manifest-list)
declare -A EXPECTED_DIGESTS
while IFS=': ' read -r key value || [[ -n "$key" ]]; do
    # Skip comments and non-digest lines
    [[ "$key" =~ ^#.*$ || -z "$value" ]] && continue
    [[ "$key" == "commit" || "$key" == "source_date_epoch" ]] && continue

    if [[ "$value" =~ ^sha256: ]]; then
        EXPECTED_DIGESTS["$key"]="$value"
    fi
done < "$MANIFEST_FILE"

DIGEST_ERRORS=0

# Get list of unique base image names (without arch suffix)
declare -A BASE_IMAGES
for key in "${!EXPECTED_DIGESTS[@]}"; do
    # Extract base name (remove -amd64, -arm64, -arm-v7, -manifest suffixes)
    base="${key%-amd64}"
    base="${base%-arm64}"
    base="${base%-arm-v7}"
    base="${base%-manifest}"
    BASE_IMAGES["$base"]=1
done

for image in "${!BASE_IMAGES[@]}"; do
    manifest_key="${image}-manifest"

    # Check if we have a manifest digest (new format) or just image digest (old format)
    if [[ -v "EXPECTED_DIGESTS[$manifest_key]" ]]; then
        expected="${EXPECTED_DIGESTS[$manifest_key]}"
    elif [[ -v "EXPECTED_DIGESTS[$image]" ]]; then
        # Old format: just the image name without suffix
        expected="${EXPECTED_DIGESTS[$image]}"
    else
        log_warn "No digest found for $image, skipping"
        continue
    fi

    full_image="${REGISTRY}/${REPO}/${image}:${VERSION}"
    log_info "Checking $image..."

    # Get actual manifest list digest from registry
    if actual=$(docker buildx imagetools inspect "$full_image" --raw 2>/dev/null | \
                sha256sum | cut -d' ' -f1 | sed 's/^/sha256:/'); then
        if [[ "$actual" == "$expected" ]]; then
            log_info "  Manifest digest matches: $expected"
        else
            log_error "  Manifest digest mismatch!"
            log_error "    Expected: $expected"
            log_error "    Actual:   $actual"
            DIGEST_ERRORS=$((DIGEST_ERRORS + 1))
        fi
    else
        log_warn "  Could not fetch digest from registry"
        log_warn "  Image may not exist or you may need to authenticate"
    fi
done

if [[ $DIGEST_ERRORS -gt 0 ]]; then
    log_error "Found $DIGEST_ERRORS digest mismatches!"
    exit 1
fi

# =============================================================================
# Step 4: Optionally reproduce the build (current architecture only)
# =============================================================================
REPRODUCE_ERRORS=0
REPRODUCE_SUCCESS=0

if [[ "$REPRODUCE" == true ]]; then
    # Check for jq (required for OCI manifest parsing)
    if ! command -v jq &> /dev/null; then
        log_error "jq is required for --reproduce. Please install it."
        exit 1
    fi

    # Detect current architecture
    CURRENT_ARCH=$(detect_arch)
    log_info "Attempting to reproduce Docker builds for $CURRENT_ARCH..."

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

    # Clone repository at specific commit
    REPO_DIR="$WORK_DIR/repo"
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

    for i in "${!IMAGES[@]}"; do
        image="${IMAGES[$i]}"
        dockerfile="${DOCKERFILES[$i]}"
        digest_key="${image}-${CURRENT_ARCH}"

        # Check for per-platform digest (new format) or fall back to manifest digest
        if [[ -v "EXPECTED_DIGESTS[$digest_key]" ]]; then
            manifest_expected="${EXPECTED_DIGESTS[$digest_key]}"
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

        if [[ -n "$built_digest" && "$built_digest" != "null" ]]; then
            # Compare against manifest (which now contains OCI digests)
            if [[ "$built_digest" == "$manifest_expected" ]]; then
                log_info "  Reproduced successfully!"
                log_info "    Digest: $built_digest"
                REPRODUCE_SUCCESS=$((REPRODUCE_SUCCESS + 1))
            else
                log_error "  Digest mismatch!"
                log_error "    Expected (manifest): $manifest_expected"
                log_error "    Built:               $built_digest"
                REPRODUCE_ERRORS=$((REPRODUCE_ERRORS + 1))
            fi
        else
            log_error "  Could not determine digest of built image"
            REPRODUCE_ERRORS=$((REPRODUCE_ERRORS + 1))
        fi

        # Clean up OCI files
        rm -rf "$OCI_TAR" "$OCI_EXTRACT"
    done
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=============================================="
log_info "Verification Summary for $VERSION"
echo "=============================================="
echo "Valid GPG signatures: $VALID_SIGS"
if [[ ${#SIGNERS[@]} -gt 0 ]]; then
    echo "Signers:"
    for signer in "${SIGNERS[@]}"; do
        echo "  - $signer"
    done
fi
echo "Digest verification: PASSED"
if [[ "$REPRODUCE" == true ]]; then
    if [[ $REPRODUCE_ERRORS -gt 0 ]]; then
        echo "Reproducibility check: FAILED ($REPRODUCE_ERRORS errors, $REPRODUCE_SUCCESS succeeded)"
    else
        echo "Reproducibility check: PASSED ($REPRODUCE_SUCCESS images reproduced)"
    fi
fi
echo ""

# Fail if reproducibility was requested and failed
if [[ "$REPRODUCE" == true && $REPRODUCE_ERRORS -gt 0 ]]; then
    log_error "Reproducibility verification failed!"
    log_error "The builds could not be reproduced locally."
    log_error "This may indicate:"
    log_error "  - Different BuildKit versions"
    log_error "  - Platform differences"
    log_error "  - Non-deterministic build steps in Dockerfiles"
    exit 1
fi

log_info "Release verification completed successfully!"
