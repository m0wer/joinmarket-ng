#!/bin/bash
# Update all dependency lock files in the JoinMarket NG monorepo
#
# Usage:
#   ./scripts/update-deps.sh              # Update all dependencies
#   ./scripts/update-deps.sh --dev-only   # Update only dev dependencies
#   ./scripts/update-deps.sh --prod-only  # Update only production dependencies

set -e

PACKAGES="jmcore directory_server orderbook_watcher jmwallet maker taker"
UPDATE_PROD=true
UPDATE_DEV=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev-only)
            UPDATE_PROD=false
            shift
            ;;
        --prod-only)
            UPDATE_DEV=false
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--dev-only|--prod-only]"
            exit 1
            ;;
    esac
done

echo "========================================="
echo "Updating JoinMarket NG Dependencies"
echo "========================================="
echo ""

if [ "$UPDATE_PROD" = true ]; then
    echo "Updating production dependencies..."
    echo ""

    for dir in $PACKAGES; do
        echo "=== $dir ==="
        cd "$dir"

        if [ "$dir" = "jmcore" ]; then
            # jmcore has no local deps, compile directly
            pip-compile --strip-extras --generate-hashes pyproject.toml -o requirements.txt
        else
            # For other packages, we need to temporarily remove local package references
            # from pyproject.toml because pip-compile can't resolve them from PyPI.
            cp pyproject.toml pyproject.toml.bak

            # Remove jmcore and jmwallet lines
            # REQUIRE INDENTATION to avoid removing 'name = "jmwallet"'
            sed -i '/^[[:space:]][[:space:]]*"jmcore"/d' pyproject.toml
            sed -i '/^[[:space:]][[:space:]]*"jmwallet"/d' pyproject.toml

            # Compile
            pip-compile --strip-extras --generate-hashes pyproject.toml -o requirements.txt

            # Restore original pyproject.toml
            mv pyproject.toml.bak pyproject.toml
        fi

        cd ..
        echo ""
    done
fi

if [ "$UPDATE_DEV" = true ]; then
    echo "Updating development dependencies..."
    echo ""

    for dir in $PACKAGES; do
        echo "=== $dir (dev) ==="
        cd "$dir"

        if [ "$dir" = "jmcore" ]; then
            pip-compile --strip-extras --generate-hashes --extra dev pyproject.toml -o requirements-dev.txt
        else
            cp pyproject.toml pyproject.toml.bak
            sed -i '/^[[:space:]][[:space:]]*"jmcore"/d' pyproject.toml
            sed -i '/^[[:space:]][[:space:]]*"jmwallet"/d' pyproject.toml

            # Compile dev deps
            pip-compile --strip-extras --generate-hashes --extra dev pyproject.toml -o requirements-dev.txt

            # Restore original
            mv pyproject.toml.bak pyproject.toml
        fi

        cd ..
        echo ""
    done
fi

echo "========================================="
echo "All dependencies updated successfully"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff */requirements*.txt"
echo "  2. Test locally: pip install -r <package>/requirements-dev.txt"
echo "  3. Run tests: pytest"
echo "  4. Commit: git add */requirements*.txt && git commit"
