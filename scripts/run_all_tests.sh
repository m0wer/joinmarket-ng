#!/bin/bash
set -euo pipefail

# JoinMarket Complete Test Suite Runner
# Runs all tests in optimal order with proper cleanup
#
# This script uses --fail-on-skip to ensure that if tests are selected by markers
# but skipped due to missing setup conditions, the suite will fail. This helps
# catch configuration issues in CI.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_info "Working directory: $PROJECT_ROOT"

# Test results tracking
FAILED_TESTS=()
COVERAGE_FILES=()

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Complete cleanup function
cleanup_all() {
    log_info "Performing complete cleanup..."

    # Stop all profiles
    docker compose --profile e2e --profile reference --profile neutrino --profile reference-maker down -v 2>/dev/null || true

    # Remove any orphaned containers
    docker compose down --remove-orphans -v 2>/dev/null || true

    # Force remove any containers with jm- prefix that might be stuck
    STUCK_CONTAINERS=$(docker ps -aq -f "name=jm-" 2>/dev/null || true)
    if [ -n "$STUCK_CONTAINERS" ]; then
        log_warning "Found stuck containers, force removing..."
        echo "$STUCK_CONTAINERS" | xargs docker rm -f 2>/dev/null || true
    fi

    # Clean up any dangling volumes
    docker volume prune -f >/dev/null 2>&1 || true

    log_success "Cleanup complete"
}

# Wait for service with timeout
wait_for_service() {
    local service=$1
    local max_attempts=${2:-30}
    local attempt=0

    log_info "Waiting for $service..."
    while [ $attempt -lt $max_attempts ]; do
        if docker compose ps "$service" 2>/dev/null | grep -q "healthy\|running"; then
            log_success "$service is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done

    log_error "$service failed to start"
    return 1
}

# Wait for Bitcoin RPC
wait_for_bitcoin() {
    local rpc_port=${1:-18443}
    log_info "Waiting for Bitcoin RPC on port $rpc_port..."

    for i in {1..30}; do
        if docker compose exec -T bitcoin bitcoin-cli -chain=regtest \
            -rpcport="$rpc_port" -rpcuser=test -rpcpassword=test getblockchaininfo >/dev/null 2>&1; then
            log_success "Bitcoin RPC ready"
            return 0
        fi
        sleep 2
    done

    log_error "Bitcoin RPC timeout"
    return 1
}

# Wait for Neutrino sync
wait_for_neutrino() {
    log_info "Waiting for Neutrino to sync..."

    for i in {1..60}; do
        if curl -s http://localhost:8334/v1/status 2>/dev/null | grep -q '"synced":true'; then
            log_success "Neutrino synced!"
            return 0
        fi
        echo "  Attempt $i/60: Neutrino syncing..."
        sleep 5
    done

    log_error "Neutrino sync timeout"
    return 1
}

# Run tests and track results (always returns success to continue with other tests)
run_test_suite() {
    local test_name=$1
    shift

    log_info "Running $test_name..."
    log_info "Command: pytest -c \"$PROJECT_ROOT/pytest.ini\" --fail-on-skip $*"

    if pytest -c "$PROJECT_ROOT/pytest.ini" --fail-on-skip "$@"; then
        log_success "$test_name passed"
    else
        log_error "$test_name failed"
        FAILED_TESTS+=("$test_name")
    fi

    # Always return success to continue running other test suites
    return 0
}

# Restart makers to sync blockchain state
restart_makers() {
    log_info "Restarting makers to sync blockchain state..."
    docker compose restart maker1 maker2 2>/dev/null || true
    sleep 10
    log_success "Makers restarted"
}

# Main test execution
main() {
    log_info "=== JoinMarket Complete Test Suite ==="
    log_info "Starting at $(date)"
    echo

    # Ensure we cleanup on exit
    trap 'log_info "Cleaning up on exit..."; cleanup_all' EXIT

    # Initial cleanup
    cleanup_all

    # ========================================================================
    # Phase 1: Unit Tests (No Docker Required)
    # ========================================================================
    log_info "=== Phase 1: Unit Tests ==="

    # Note: pytest.ini already has '-m "not docker"' as default, so Docker tests
    # in maker/tests/integration/ are automatically excluded
    run_test_suite "Unit Tests" \
        -lv \
        --cov=jmcore --cov=jmwallet --cov=directory_server \
        --cov=orderbook_watcher --cov=maker --cov=taker \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/unit \
        jmcore/ jmwallet/ directory_server/ orderbook_watcher/ maker/ taker/

    # Save unit test coverage
    if [ -f .coverage ]; then
        cp .coverage .coverage.unit
        COVERAGE_FILES+=(".coverage.unit")
        log_info "Saved unit test coverage"
    else
        log_warning "No .coverage file found for unit tests"
    fi

    echo

    # ========================================================================
    # Phase 2: E2E Tests (Our Implementation)
    # ========================================================================
    log_info "=== Phase 2: E2E Tests (Our Implementation) ==="

    log_info "Starting e2e profile..."
    docker compose --profile e2e up -d --build

    wait_for_bitcoin 18443
    log_info "Waiting for wallet funding (30s)..."
    sleep 30
    restart_makers

    # Run e2e tests from tests/ directory
    run_test_suite "E2E Tests" \
        -lv -m e2e \
        --cov=jmcore --cov=jmwallet --cov=directory_server \
        --cov=orderbook_watcher --cov=maker --cov=taker \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/e2e \
        tests/

    # Run Docker integration tests from component directories (e.g., maker/tests/integration/)
    # These are marked with @pytest.mark.docker but not with e2e/reference/neutrino
    # Run from project root to ensure conftest.py is loaded
    run_test_suite "Docker Integration Tests" \
        -lv -m "docker and not e2e and not reference and not neutrino and not reference_maker" \
        --cov=jmcore --cov=jmwallet --cov=directory_server \
        --cov=orderbook_watcher --cov=maker --cov=taker \
        --cov-append \
        --cov-report=term-missing \
        "$PROJECT_ROOT/maker/tests/integration/" \
        "$PROJECT_ROOT/jmwallet/tests/"

    # Save e2e coverage
    if [ -f .coverage ]; then
        cp .coverage .coverage.e2e
        COVERAGE_FILES+=(".coverage.e2e")
        log_info "Saved e2e coverage"
    else
        log_warning "No .coverage file found for e2e tests"
    fi

    echo

    # ========================================================================
    # Phase 3: Reference Tests (Add JAM to existing e2e setup)
    # ========================================================================
    log_info "=== Phase 3: Reference Compatibility Tests ==="

    log_info "Starting reference profile components (keeping e2e running)..."
    docker compose --profile reference up -d --build

    # Wait for reference-specific services
    log_info "Waiting for Tor to generate hidden service..."
    for i in {1..60}; do
        if docker compose exec -T tor cat /var/lib/tor/directory/hostname 2>/dev/null | grep -q ".onion"; then
            log_success "Tor hidden service ready"
            break
        fi
        sleep 2
    done

    log_info "Waiting for JAM to start (60s)..."
    sleep 60
    restart_makers

    run_test_suite "Reference Tests" \
        -lv -m reference \
        --cov=jmcore --cov=jmwallet --cov=directory_server \
        --cov=orderbook_watcher --cov=maker --cov=taker \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/reference \
        tests/

    # Save reference coverage
    if [ -f .coverage ]; then
        cp .coverage .coverage.reference
        COVERAGE_FILES+=(".coverage.reference")
        log_info "Saved reference test coverage"
    else
        log_warning "No .coverage file found for reference tests"
    fi

    echo

    # ========================================================================
    # Phase 4: Reference Maker Tests (Our Taker + JAM Makers)
    # ========================================================================
    log_info "=== Phase 4: Reference Maker Tests ==="

    log_info "Stopping our makers and starting JAM makers..."
    docker compose stop maker1 maker2
    docker compose --profile reference-maker up -d

    log_info "Waiting for JAM makers to start (60s)..."
    sleep 60

    run_test_suite "Reference Maker Tests" \
        -lv -m reference_maker \
        --cov=taker \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/reference_maker \
        tests/

    # Save reference maker coverage
    if [ -f .coverage ]; then
        cp .coverage .coverage.reference_maker
        COVERAGE_FILES+=(".coverage.reference_maker")
        log_info "Saved reference maker coverage"
    else
        log_warning "No .coverage file found for reference maker tests"
    fi

    echo

    # ========================================================================
    # Phase 5: Neutrino Tests (Fresh Setup)
    # ========================================================================
    log_info "=== Phase 5: Neutrino Backend Tests ==="

    log_info "Stopping e2e and reference profiles..."
    docker compose --profile e2e --profile reference --profile reference-maker down -v

    log_info "Starting neutrino profile..."
    docker compose --profile neutrino up -d --build

    wait_for_bitcoin 18443
    wait_for_neutrino

    log_info "Waiting for wallet funding (30s)..."
    sleep 30

    # Run basic neutrino tests
    run_test_suite "Neutrino Basic Tests" \
        -lv -m "neutrino and not slow" \
        --cov=jmcore --cov=jmwallet --cov=maker \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/neutrino \
        tests/

    # Save neutrino coverage
    if [ -f .coverage ]; then
        cp .coverage .coverage.neutrino
        COVERAGE_FILES+=(".coverage.neutrino")
        log_info "Saved neutrino basic test coverage"
    else
        log_warning "No .coverage file found for neutrino tests"
    fi

    # For neutrino coinjoin tests, also start e2e makers
    log_info "Starting e2e makers for neutrino coinjoin tests..."
    docker compose --profile e2e up -d
    sleep 10
    restart_makers

    run_test_suite "Neutrino CoinJoin Tests" \
        -lv -m 'neutrino and slow' \
        --cov=jmcore --cov=jmwallet --cov=maker --cov=taker \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/neutrino_slow \
        tests/

    # Save neutrino slow coverage
    if [ -f .coverage ]; then
        cp .coverage .coverage.neutrino_slow
        COVERAGE_FILES+=(".coverage.neutrino_slow")
        log_info "Saved neutrino coinjoin test coverage"
    else
        log_warning "No .coverage file found for neutrino slow tests"
    fi

    echo

    # ========================================================================
    # Combine Coverage Reports
    # ========================================================================
    if [ ${#COVERAGE_FILES[@]} -gt 0 ]; then
        log_info "=== Combining Coverage Reports ==="

        # Combine all coverage files
        coverage combine "${COVERAGE_FILES[@]}"

        # Generate combined reports
        coverage report --skip-covered
        coverage html -d htmlcov/combined
        coverage xml -o coverage.xml

        log_success "Combined coverage report: htmlcov/combined/index.html"
    fi

    echo

    # ========================================================================
    # Summary
    # ========================================================================
    echo
    echo "========================================================================"
    log_info "=== Test Suite Summary ==="
    log_info "Completed at $(date)"
    echo "========================================================================"
    echo

    if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
        log_success "✓ All test suites passed!"
        echo
        log_info "Test phases completed:"
        echo "  ✓ Unit Tests"
        echo "  ✓ E2E Tests"
        echo "  ✓ Docker Integration Tests"
        echo "  ✓ Reference Compatibility Tests"
        echo "  ✓ Reference Maker Tests"
        echo "  ✓ Neutrino Basic Tests"
        echo "  ✓ Neutrino CoinJoin Tests"
        echo
        if [ ${#COVERAGE_FILES[@]} -gt 0 ]; then
            log_info "Coverage reports:"
            echo "  - Combined: htmlcov/combined/index.html"
            echo "  - XML: coverage.xml"
        fi
        exit 0
    else
        log_error "✗ Some test suites failed"
        echo
        log_error "Failed test suites (${#FAILED_TESTS[@]}):"
        for test in "${FAILED_TESTS[@]}"; do
            echo "  ✗ $test"
        done
        echo
        log_info "Check the output above for details on failed tests"
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    --cleanup-only)
        cleanup_all
        log_success "Cleanup complete"
        exit 0
        ;;
    --help|-h)
        cat <<EOF
JoinMarket Complete Test Suite Runner

Usage: $0 [OPTIONS]

Options:
    (no args)       Run complete test suite
    --cleanup-only  Only perform cleanup and exit
    --help, -h      Show this help message

The script runs all tests in this order:
1. Unit tests (no Docker)
2. E2E tests (our implementation) + Docker integration tests
3. Reference tests (JAM compatibility)
4. Reference maker tests (JAM makers + our taker)
5. Neutrino tests (light client backend)

Coverage reports are generated for each phase and combined at the end.
All Docker resources are cleaned up before and after the run.

IMPORTANT: Uses --fail-on-skip to ensure tests don't silently skip.
If tests are selected by markers but skip due to missing setup,
the suite will fail. This catches configuration issues in CI.

All pytest commands use '-c pytest.ini' to ensure the root conftest.py
is loaded, which registers the --fail-on-skip option.

EOF
        exit 0
        ;;
    "")
        main
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
