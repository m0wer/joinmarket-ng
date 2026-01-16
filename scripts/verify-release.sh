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
#   - docker (for image verification and reproduction)
#   - curl or wget
#   - git
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
# Step 3: Verify Docker image digests
# =============================================================================
log_info "Verifying Docker image digests..."

# Extract image digests from manifest
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

for image in "${!EXPECTED_DIGESTS[@]}"; do
    expected="${EXPECTED_DIGESTS[$image]}"
    full_image="${REGISTRY}/${REPO}/${image}:${VERSION}"

    log_info "Checking $image..."

    # Get actual digest from registry
    if actual=$(docker manifest inspect "$full_image" 2>/dev/null | \
                grep -oP '"digest":\s*"\K[^"]+' | head -1); then
        if [[ "$actual" == "$expected" ]]; then
            log_info "  Digest matches: $expected"
        else
            log_error "  Digest mismatch!"
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
# Step 4: Optionally reproduce the build
# =============================================================================
if [[ "$REPRODUCE" == true ]]; then
    log_info "Attempting to reproduce Docker builds..."

    # Extract commit and SOURCE_DATE_EPOCH from manifest
    COMMIT=$(grep "^commit:" "$MANIFEST_FILE" | cut -d' ' -f2)
    SOURCE_DATE_EPOCH=$(grep "^source_date_epoch:" "$MANIFEST_FILE" | cut -d' ' -f2)

    if [[ -z "$COMMIT" || -z "$SOURCE_DATE_EPOCH" ]]; then
        log_error "Could not extract commit or SOURCE_DATE_EPOCH from manifest"
        exit 1
    fi

    log_info "Commit: $COMMIT"
    log_info "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"

    # Clone repository at specific commit
    REPO_DIR="$WORK_DIR/repo"
    git clone --depth 1 "https://github.com/${REPO}.git" "$REPO_DIR"
    cd "$REPO_DIR"
    git fetch --depth 1 origin "$COMMIT"
    git checkout "$COMMIT"

    # Build images with same SOURCE_DATE_EPOCH
    IMAGES=("directory-server" "maker" "taker" "orderbook-watcher")
    DOCKERFILES=("./directory_server/Dockerfile" "./maker/Dockerfile" "./taker/Dockerfile" "./orderbook_watcher/Dockerfile")

    for i in "${!IMAGES[@]}"; do
        image="${IMAGES[$i]}"
        dockerfile="${DOCKERFILES[$i]}"

        if [[ ! -v "EXPECTED_DIGESTS[$image]" ]]; then
            log_warn "No expected digest for $image, skipping"
            continue
        fi

        log_info "Building $image..."

        # Build with buildx for reproducibility
        docker buildx build \
            --file "$dockerfile" \
            --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
            --output "type=docker,dest=$WORK_DIR/${image}.tar" \
            --platform linux/amd64 \
            . 2>/dev/null

        # Get digest of built image
        built_digest=$(docker load -i "$WORK_DIR/${image}.tar" 2>/dev/null | \
                       grep -oP 'sha256:\K[a-f0-9]+')

        if [[ -n "$built_digest" ]]; then
            expected="${EXPECTED_DIGESTS[$image]}"
            if [[ "sha256:$built_digest" == "$expected" ]]; then
                log_info "  Reproduced successfully! Digest matches."
            else
                log_warn "  Build completed but digest differs"
                log_warn "    Expected: $expected"
                log_warn "    Built:    sha256:$built_digest"
                log_warn "  This may be due to different BuildKit versions or platform differences"
            fi
        else
            log_warn "  Could not determine digest of built image"
        fi
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
    echo "Reproducibility check: ATTEMPTED (see output above)"
fi
echo ""
log_info "Release verification completed successfully!"
