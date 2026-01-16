#!/usr/bin/env bash
# =============================================================================
# JoinMarket NG Release Signing Script
#
# This script helps trusted parties sign release manifests.
#
# Usage:
#   ./scripts/sign-release.sh <version> [--key <fingerprint>]
#
# Requirements:
#   - gpg (GnuPG) with a valid signing key
#   - curl or wget
#   - git
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
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

Sign a JoinMarket NG release manifest.

Arguments:
  version         Release version to sign (e.g., 1.0.0)

Options:
  --key KEY       GPG key fingerprint to use for signing
  --verify-first  Verify reproducibility before signing (recommended)
  --help          Show this help message

Examples:
  $(basename "$0") 1.0.0
  $(basename "$0") 1.0.0 --key ABCD1234...
  $(basename "$0") 1.0.0 --verify-first
EOF
    exit 1
}

# Parse arguments
VERSION=""
GPG_KEY=""
VERIFY_FIRST=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --key)
            GPG_KEY="$2"
            shift 2
            ;;
        --verify-first)
            VERIFY_FIRST=true
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

if [[ -z "$VERSION" ]]; then
    log_error "Version is required"
    usage
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
# Step 2: Optionally verify reproducibility
# =============================================================================
if [[ "$VERIFY_FIRST" == true ]]; then
    log_info "Verifying release before signing..."
    "$SCRIPT_DIR/verify-release.sh" "$VERSION" --reproduce || {
        log_error "Verification failed! Not signing."
        exit 1
    }
fi

# =============================================================================
# Step 3: Get GPG key
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
echo "Next steps:"
echo "1. Review the signature file"
echo "2. Commit and push your signature:"
echo "   git add $SIG_FILE"
echo "   git commit -m 'Add GPG signature for release $VERSION'"
echo "   git push"
echo ""
echo "3. Or create a PR with your signature if you don't have write access"
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
