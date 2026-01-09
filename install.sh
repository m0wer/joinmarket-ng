#!/usr/bin/env bash
#
# JoinMarket-NG Installation Script
# Automated installation with virtual environment setup
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VENV_DIR="jmvenv"
PYTHON_MIN_VERSION="3.11"

# Helper functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check system dependencies
check_system_dependencies() {
    print_header "Checking System Dependencies"

    local missing_deps=()
    local os_type=""

    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        os_type="linux"
        # Check for Debian/Ubuntu-based systems
        if command -v apt &> /dev/null; then
            # Check for required build tools
            if ! dpkg -s build-essential &> /dev/null; then
                missing_deps+=("build-essential")
            fi
            if ! dpkg -s libffi-dev &> /dev/null; then
                missing_deps+=("libffi-dev")
            fi
            if ! dpkg -s libsodium-dev &> /dev/null; then
                missing_deps+=("libsodium-dev")
            fi
            if ! dpkg -s pkg-config &> /dev/null; then
                missing_deps+=("pkg-config")
            fi
            if ! dpkg -s python3-venv &> /dev/null; then
                missing_deps+=("python3-venv")
            fi
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        os_type="macos"
        # Check for Homebrew
        if ! command -v brew &> /dev/null; then
            print_warning "Homebrew not found. Install from https://brew.sh"
        else
            # Check for required packages
            if ! brew list libsodium &> /dev/null 2>&1; then
                missing_deps+=("libsodium")
            fi
            if ! brew list pkg-config &> /dev/null 2>&1; then
                missing_deps+=("pkg-config")
            fi
        fi
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_warning "Missing system dependencies: ${missing_deps[*]}"
        echo ""
        echo "Please install the required dependencies:"
        echo ""
        if [[ "$os_type" == "linux" ]]; then
            echo "  sudo apt update"
            echo "  sudo apt install -y ${missing_deps[*]}"
        elif [[ "$os_type" == "macos" ]]; then
            echo "  brew install ${missing_deps[*]}"
        fi
        echo ""
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "All system dependencies are installed"
    fi
}

# Check and setup Tor
setup_tor() {
    print_header "Setting Up Tor"

    local os_type=""
    local tor_installed=false

    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        os_type="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        os_type="macos"
    fi

    # Check if Tor is installed
    if command -v tor &> /dev/null; then
        tor_installed=true
        print_success "Tor is already installed"
    else
        print_warning "Tor is not installed"
        echo ""
        echo "JoinMarket-NG requires Tor for privacy and anonymity."
        echo ""
        read -p "Do you want to install Tor now? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            print_info "Installing Tor..."
            if [[ "$os_type" == "linux" ]]; then
                if command -v apt &> /dev/null; then
                    sudo apt update
                    sudo apt install -y tor
                    tor_installed=true
                else
                    print_warning "Automatic Tor installation not supported on this system"
                    echo "Please install Tor manually and re-run this script"
                fi
            elif [[ "$os_type" == "macos" ]]; then
                if command -v brew &> /dev/null; then
                    brew install tor
                    tor_installed=true
                else
                    print_warning "Homebrew not found. Please install from https://brew.sh"
                    echo "Then run: brew install tor"
                fi
            fi
        else
            print_warning "Skipping Tor installation"
            echo "You will need to install Tor manually before using JoinMarket-NG"
            return 0
        fi
    fi

    if [ "$tor_installed" = false ]; then
        print_warning "Tor installation was not completed"
        return 0
    fi

    # Configure Tor for JoinMarket use
    print_info "Configuring Tor for JoinMarket..."

    local torrc_path=""
    local need_config=false

    # Determine torrc path
    if [[ "$os_type" == "linux" ]]; then
        torrc_path="/etc/tor/torrc"
    elif [[ "$os_type" == "macos" ]]; then
        if [ -d "$(brew --prefix)/etc/tor" ]; then
            torrc_path="$(brew --prefix)/etc/tor/torrc"
        else
            print_warning "Could not find Tor configuration directory"
            return 0
        fi
    fi

    # Check if torrc exists and if it has the required configuration
    if [ -f "$torrc_path" ]; then
        if ! grep -q "^ControlPort 127.0.0.1:9051" "$torrc_path" 2>/dev/null; then
            need_config=true
        fi
    else
        need_config=true
    fi

    if [ "$need_config" = true ]; then
        echo ""
        echo "Tor needs to be configured with control port access for maker bots"
        echo "to create ephemeral hidden services."
        echo ""
        echo "Required configuration (localhost-only):"
        echo "  SocksPort 127.0.0.1:9050"
        echo "  ControlPort 127.0.0.1:9051"
        echo "  CookieAuthentication 1"
        echo ""
        read -p "Do you want to configure Tor now? [Y/n] " -n 1 -r
        echo

        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            print_info "Configuring Tor..."

            # Create backup of existing torrc
            if [ -f "$torrc_path" ]; then
                sudo cp "$torrc_path" "${torrc_path}.backup.$(date +%Y%m%d_%H%M%S)"
                print_info "Created backup: ${torrc_path}.backup.$(date +%Y%m%d_%H%M%S)"
            fi

            # Append JoinMarket configuration
            sudo bash -c "cat >> $torrc_path" << 'EOF'

## JoinMarket Configuration
# SOCKS proxy for clients (bound to localhost only)
SocksPort 127.0.0.1:9050

# Control port for maker bots to create ephemeral hidden services (localhost only)
ControlPort 127.0.0.1:9051
CookieAuthentication 1
EOF

            print_success "Tor configuration updated"

            # Restart Tor to apply changes
            print_info "Restarting Tor..."
            if [[ "$os_type" == "linux" ]]; then
                if command -v systemctl &> /dev/null; then
                    sudo systemctl restart tor
                    sudo systemctl enable tor
                    print_success "Tor restarted and enabled"
                else
                    print_warning "Could not restart Tor automatically"
                    echo "Please restart Tor manually: sudo service tor restart"
                fi
            elif [[ "$os_type" == "macos" ]]; then
                if brew services list | grep -q "^tor.*started"; then
                    brew services restart tor
                else
                    brew services start tor
                fi
                print_success "Tor started"
            fi

            # Verify Tor is running
            sleep 2
            if nc -z 127.0.0.1 9050 2>/dev/null; then
                print_success "Tor SOCKS proxy is accessible on 127.0.0.1:9050"
            else
                print_warning "Could not verify Tor SOCKS proxy"
            fi

            if nc -z 127.0.0.1 9051 2>/dev/null; then
                print_success "Tor control port is accessible on 127.0.0.1:9051"
            else
                print_warning "Could not verify Tor control port"
            fi
        else
            print_warning "Skipping Tor configuration"
            echo ""
            echo "You will need to manually configure Tor. See INSTALL.md for instructions."
        fi
    else
        print_success "Tor is already configured for JoinMarket"
    fi
}

# Check Python version
check_python_version() {
    print_info "Checking Python version..."

    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3.11 or higher."
        echo "  For Debian/Ubuntu: sudo apt install python3 python3-venv python3-pip"
        echo "  For macOS: brew install python3"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')

    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)"; then
        print_success "Python $PYTHON_VERSION detected (minimum: $PYTHON_MIN_VERSION)"
    else
        print_error "Python $PYTHON_VERSION is too old. Minimum required: $PYTHON_MIN_VERSION"
        echo ""
        echo "  For Debian/Ubuntu:"
        echo "    sudo apt install software-properties-common"
        echo "    sudo add-apt-repository ppa:deadsnakes/ppa"
        echo "    sudo apt update"
        echo "    sudo apt install python3.11 python3.11-venv"
        echo ""
        echo "  For macOS:"
        echo "    brew install python@3.11"
        exit 1
    fi
}

# Create virtual environment
create_virtualenv() {
    print_header "Creating Virtual Environment"

    if [ -d "$VENV_DIR" ]; then
        print_warning "Virtual environment already exists at $VENV_DIR"
        read -p "Do you want to recreate it? This will delete the existing environment. [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Removing existing virtual environment..."
            rm -rf "$VENV_DIR"
        else
            print_info "Using existing virtual environment..."
            return 0
        fi
    fi

    print_info "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    print_success "Virtual environment created"
}

# Activate virtual environment
activate_virtualenv() {
    print_info "Activating virtual environment..."
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    print_success "Virtual environment activated"
}

# Upgrade pip
upgrade_pip() {
    print_info "Upgrading pip..."
    pip install --upgrade pip
    print_success "pip upgraded"
}

# Install core libraries
install_core() {
    print_header "Installing Core Libraries"

    print_info "Installing jmcore..."
    cd jmcore
    pip install -e .
    cd ..
    print_success "jmcore installed"

    print_info "Installing jmwallet..."
    cd jmwallet
    pip install -e .
    cd ..
    print_success "jmwallet installed"
}

# Ask user which components to install
ask_components() {
    print_header "Component Selection"

    echo "Which components would you like to install?"
    echo ""
    echo "  1) Maker only (earn fees by providing liquidity)"
    echo "  2) Taker only (mix your coins for privacy)"
    echo "  3) Both Maker and Taker"
    echo "  4) Skip component installation (core libraries only)"
    echo ""

    read -p "Enter your choice [1-4]: " -n 1 -r
    echo

    case $REPLY in
        1)
            INSTALL_MAKER=true
            INSTALL_TAKER=false
            ;;
        2)
            INSTALL_MAKER=false
            INSTALL_TAKER=true
            ;;
        3)
            INSTALL_MAKER=true
            INSTALL_TAKER=true
            ;;
        4)
            INSTALL_MAKER=false
            INSTALL_TAKER=false
            ;;
        *)
            print_warning "Invalid choice. Skipping component installation."
            INSTALL_MAKER=false
            INSTALL_TAKER=false
            ;;
    esac
}

# Install maker
install_maker() {
    print_header "Installing Maker Bot"

    print_info "Installing maker..."
    cd maker
    pip install -e .
    cd ..
    print_success "Maker bot installed"
}

# Install taker
install_taker() {
    print_header "Installing Taker Bot"

    print_info "Installing taker..."
    cd taker
    pip install -e .
    cd ..
    print_success "Taker bot installed"
}

# Ask about development dependencies
ask_dev_dependencies() {
    print_header "Development Dependencies"

    echo "Do you want to install development dependencies?"
    echo "This includes testing tools (pytest, ruff, mypy, etc.)"
    echo ""

    read -p "Install development dependencies? [y/N] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        INSTALL_DEV=true
    else
        INSTALL_DEV=false
    fi
}

# Install development dependencies
install_dev_dependencies() {
    print_header "Installing Development Dependencies"

    print_info "Installing jmcore dev dependencies..."
    cd jmcore
    pip install -r requirements-dev.txt
    cd ..

    print_info "Installing jmwallet dev dependencies..."
    cd jmwallet
    pip install -r requirements-dev.txt
    cd ..

    if [ "$INSTALL_MAKER" = true ]; then
        print_info "Installing maker dev dependencies..."
        cd maker
        pip install -r requirements-dev.txt
        cd ..
    fi

    if [ "$INSTALL_TAKER" = true ]; then
        print_info "Installing taker dev dependencies..."
        cd taker
        pip install -r requirements-dev.txt
        cd ..
    fi

    print_success "Development dependencies installed"
}

# Create data directory
create_data_directory() {
    print_header "Setting Up Data Directory"

    DATA_DIR="$HOME/.joinmarket-ng"

    if [ -d "$DATA_DIR" ]; then
        print_info "Data directory already exists at $DATA_DIR"
    else
        print_info "Creating data directory at $DATA_DIR..."
        mkdir -p "$DATA_DIR/wallets"
        chmod 700 "$DATA_DIR"
        chmod 700 "$DATA_DIR/wallets"
        print_success "Data directory created"
    fi
}

# Print next steps
print_next_steps() {
    print_header "Installation Complete!"

    echo "To start using JoinMarket-NG:"
    echo ""
    echo -e "${GREEN}1. Activate the virtual environment:${NC}"
    echo "   source $VENV_DIR/bin/activate"
    echo ""

    if [ "$INSTALL_MAKER" = true ] || [ "$INSTALL_TAKER" = true ]; then
        echo -e "${GREEN}2. Create a wallet:${NC}"
        echo "   jm-wallet generate --save --prompt-password --output ~/.joinmarket-ng/wallets/wallet.mnemonic"
        echo ""
    fi

    if [ "$INSTALL_MAKER" = true ]; then
        echo -e "${GREEN}3. Start the maker bot:${NC}"
        echo "   See maker/README.md for detailed instructions"
        echo "   Quick start: jm-maker start --mnemonic-file ~/.joinmarket-ng/wallets/wallet.mnemonic"
        echo ""
    fi

    if [ "$INSTALL_TAKER" = true ]; then
        echo -e "${GREEN}3. Execute a CoinJoin:${NC}"
        echo "   See taker/README.md for detailed instructions"
        echo "   Quick start: jm-taker coinjoin --mnemonic-file ~/.joinmarket-ng/wallets/wallet.mnemonic --amount 1000000"
        echo ""
    fi

    echo -e "${BLUE}For more information:${NC}"
    echo "  - Installation guide: INSTALL.md"
    echo "  - Project README: README.md"
    echo "  - Architecture docs: DOCS.md"
    if [ "$INSTALL_MAKER" = true ]; then
        echo "  - Maker guide: maker/README.md"
    fi
    if [ "$INSTALL_TAKER" = true ]; then
        echo "  - Taker guide: taker/README.md"
    fi
    echo ""
    echo -e "${YELLOW}IMPORTANT:${NC} You'll need to activate the virtual environment every time"
    echo -e "you open a new terminal: ${GREEN}source $VENV_DIR/bin/activate${NC}"
    echo ""
}

# Show help
show_help() {
    cat << EOF
JoinMarket-NG Installation Script

Usage: $0 [OPTIONS]

Options:
  -h, --help              Show this help message
  -y, --yes               Automatic yes to prompts (install maker and taker)
  -m, --maker-only        Install maker only
  -t, --taker-only        Install taker only
  -c, --core-only         Install core libraries only
  -d, --dev               Install development dependencies
  --no-dev                Skip development dependencies (default)
  --skip-tor              Skip Tor installation and configuration

Examples:
  $0                      Interactive installation
  $0 -y                   Install everything automatically
  $0 -m                   Install maker only
  $0 -t -d                Install taker with dev dependencies
  $0 --skip-tor           Install without setting up Tor

EOF
}

# Parse command line arguments
parse_args() {
    INTERACTIVE=true
    INSTALL_MAKER=false
    INSTALL_TAKER=false
    INSTALL_DEV=false
    SKIP_TOR=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -y|--yes)
                INTERACTIVE=false
                INSTALL_MAKER=true
                INSTALL_TAKER=true
                shift
                ;;
            -m|--maker-only)
                INTERACTIVE=false
                INSTALL_MAKER=true
                INSTALL_TAKER=false
                shift
                ;;
            -t|--taker-only)
                INTERACTIVE=false
                INSTALL_MAKER=false
                INSTALL_TAKER=true
                shift
                ;;
            -c|--core-only)
                INTERACTIVE=false
                INSTALL_MAKER=false
                INSTALL_TAKER=false
                shift
                ;;
            -d|--dev)
                INSTALL_DEV=true
                shift
                ;;
            --no-dev)
                INSTALL_DEV=false
                shift
                ;;
            --skip-tor)
                SKIP_TOR=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Main installation flow
main() {
    print_header "JoinMarket-NG Installation"

    # Parse arguments
    parse_args "$@"

    # Check system dependencies
    check_system_dependencies

    # Setup Tor (unless --skip-tor is used)
    if [ "$SKIP_TOR" = false ]; then
        setup_tor
    else
        print_warning "Skipping Tor setup (--skip-tor flag used)"
    fi

    # Check Python version
    check_python_version

    # Create and activate virtual environment
    create_virtualenv
    activate_virtualenv

    # Upgrade pip
    upgrade_pip

    # Install core libraries
    install_core

    # Ask which components to install (if interactive)
    if [ "$INTERACTIVE" = true ]; then
        ask_components
        ask_dev_dependencies
    fi

    # Install selected components
    if [ "$INSTALL_MAKER" = true ]; then
        install_maker
    fi

    if [ "$INSTALL_TAKER" = true ]; then
        install_taker
    fi

    # Install dev dependencies if requested
    if [ "$INSTALL_DEV" = true ]; then
        install_dev_dependencies
    fi

    # Create data directory
    create_data_directory

    # Print next steps
    print_next_steps
}

# Run main
main "$@"
