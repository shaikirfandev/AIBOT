#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════════╗
# ║  BBHunter — Tool Installation Script                                 ║
# ║  Installs all external tools required by the Bug Bounty Suite        ║
# ║                                                                       ║
# ║  Usage:                                                               ║
# ║    chmod +x install_tools.sh                                          ║
# ║    sudo ./install_tools.sh              # Install everything          ║
# ║    sudo ./install_tools.sh --category recon     # Only recon tools    ║
# ║    sudo ./install_tools.sh --minimal            # Core tools only     ║
# ║    sudo ./install_tools.sh --check              # Check what's installed║
# ║                                                                       ║
# ║  Supported: Ubuntu/Debian, Kali Linux, Parrot OS, Arch, macOS        ║
# ╚═══════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ─── Colors & Formatting ───────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

CHECKMARK="${GREEN}✓${NC}"
CROSS="${RED}✗${NC}"
ARROW="${CYAN}→${NC}"
WARN="${YELLOW}⚠${NC}"

# ─── Globals ────────────────────────────────────────────────────────────
INSTALL_DIR="${HOME}/tools"
GO_BIN="${HOME}/go/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/install_tools.log"
INSTALLED=()
FAILED=()
SKIPPED=()
TOTAL_TOOLS=0

# ─── Arguments ──────────────────────────────────────────────────────────
CATEGORY="${1:-all}"
case "${CATEGORY}" in
    --minimal)  CATEGORY="minimal" ;;
    --check)    CATEGORY="check" ;;
    --category) CATEGORY="${2:-all}" ;;
    --help|-h)
        echo "Usage: sudo ./install_tools.sh [--minimal|--check|--category <name>|--help]"
        echo ""
        echo "Categories: recon, probing, discovery, scanner, network, secrets, params, fingerprint, crawler, utility, wordlists"
        echo "Flags:      --minimal (core tools), --check (status only)"
        exit 0
        ;;
esac

# ─── Utility Functions ─────────────────────────────────────────────────
banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
 ____  ____  _   _             _            
| __ )| __ )| | | |_   _ _ __ | |_ ___ _ __ 
|  _ \|  _ \| |_| | | | | '_ \| __/ _ \ '__|
| |_) | |_) |  _  | |_| | | | | ||  __/ |   
|____/|____/|_| |_|\__,_|_| |_|\__\___|_|   
EOF
    echo -e "${NC}"
    echo -e "${DIM}  Tool Installation Script v1.0${NC}"
    echo -e "${DIM}  $(date)${NC}"
    echo ""
}

log() {
    echo -e "$1" | tee -a "${LOG_FILE}"
}

info()    { log "  ${ARROW} $1"; }
success() { log "  ${CHECKMARK} $1"; INSTALLED+=("$2"); }
fail()    { log "  ${CROSS} ${RED}$1${NC}"; FAILED+=("$2"); }
skip()    { log "  ${WARN} ${DIM}$1 (already installed)${NC}"; SKIPPED+=("$2"); }
header()  { log "\n${PURPLE}${BOLD}═══ $1 ═══${NC}"; }

is_installed() {
    command -v "$1" &>/dev/null
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS="${ID}"
        OS_LIKE="${ID_LIKE:-}"
    elif [[ "$(uname)" == "Darwin" ]]; then
        OS="macos"
        OS_LIKE="macos"
    else
        OS="unknown"
        OS_LIKE=""
    fi
    log "  ${ARROW} Detected OS: ${BOLD}${OS}${NC} (like: ${OS_LIKE:-none})"
}

is_debian_like() {
    [[ "${OS}" == "ubuntu" || "${OS}" == "debian" || "${OS}" == "kali" || \
       "${OS}" == "parrot" || "${OS_LIKE}" == *"debian"* ]]
}

is_arch_like() {
    [[ "${OS}" == "arch" || "${OS}" == "manjaro" || "${OS_LIKE}" == *"arch"* ]]
}

is_macos() {
    [[ "${OS}" == "macos" ]]
}

ensure_go() {
    if is_installed go; then
        info "Go already installed: $(go version | head -c 30)"
        return 0
    fi

    header "Installing Go"
    local GO_VERSION="1.22.1"
    local ARCH
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
    esac

    local GO_TAR="go${GO_VERSION}.linux-${ARCH}.tar.gz"
    if is_macos; then
        GO_TAR="go${GO_VERSION}.darwin-${ARCH}.tar.gz"
    fi

    wget -q "https://go.dev/dl/${GO_TAR}" -O "/tmp/${GO_TAR}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"

    export PATH="/usr/local/go/bin:${GO_BIN}:${PATH}"

    # Persist PATH
    if ! grep -q '/usr/local/go/bin' "${HOME}/.bashrc" 2>/dev/null; then
        echo 'export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"' >> "${HOME}/.bashrc"
    fi
    if [[ -f "${HOME}/.zshrc" ]] && ! grep -q '/usr/local/go/bin' "${HOME}/.zshrc"; then
        echo 'export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"' >> "${HOME}/.zshrc"
    fi
    success "Go ${GO_VERSION} installed" "go"
}

go_install() {
    local NAME="$1"
    local PKG="$2"
    ((TOTAL_TOOLS++))

    if is_installed "${NAME}"; then
        skip "${NAME}" "${NAME}"
        return 0
    fi

    info "Installing ${BOLD}${NAME}${NC} via go install..."
    if go install "${PKG}" 2>>"${LOG_FILE}"; then
        # Ensure it's on PATH
        if [[ -f "${GO_BIN}/${NAME}" ]] && ! is_installed "${NAME}"; then
            sudo ln -sf "${GO_BIN}/${NAME}" /usr/local/bin/"${NAME}" 2>/dev/null || true
        fi
        success "${NAME} installed" "${NAME}"
    else
        fail "Failed to install ${NAME}" "${NAME}"
    fi
}

pip_install() {
    local NAME="$1"
    local PKG="${2:-$1}"
    ((TOTAL_TOOLS++))

    if is_installed "${NAME}"; then
        skip "${NAME}" "${NAME}"
        return 0
    fi

    info "Installing ${BOLD}${NAME}${NC} via pip..."
    if pip3 install --break-system-packages "${PKG}" 2>>"${LOG_FILE}" || pip3 install "${PKG}" 2>>"${LOG_FILE}"; then
        success "${NAME} installed" "${NAME}"
    else
        fail "Failed to install ${NAME}" "${NAME}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
#  STATUS CHECK MODE
# ═══════════════════════════════════════════════════════════════════════

check_status() {
    banner
    header "Tool Installation Status"

    declare -A TOOLS=(
        # ── Recon ──
        ["subfinder"]="Passive subdomain enumeration"
        ["amass"]="Advanced subdomain discovery"
        ["assetfinder"]="Fast passive subdomain finder"
        ["findomain"]="Cross-platform subdomain monitor"
        ["puredns"]="Fast DNS brute-force + wildcard"
        ["massdns"]="Ultra-fast bulk DNS resolver"
        ["shuffledns"]="massdns wrapper with wildcard filtering"
        # ── DNS ──
        ["dnsx"]="Fast DNS toolkit"
        ["dnsrecon"]="DNS enumeration tool"
        # ── URL Discovery ──
        ["gau"]="Get All URLs from archives"
        ["waybackurls"]="Wayback Machine URL fetcher"
        ["waymore"]="Enhanced wayback with more sources"
        ["katana"]="Fast web crawler with JS"
        ["gospider"]="Fast web spider"
        # ── HTTP Probing ──
        ["httpx"]="HTTP probing & tech detection"
        ["httprobe"]="Quick HTTP/HTTPS probing"
        # ── Content Discovery ──
        ["ffuf"]="Fast web fuzzer"
        ["feroxbuster"]="Recursive content discovery"
        ["gobuster"]="Directory/DNS/vhost brute-force"
        ["dirsearch"]="Directory brute-force"
        # ── Vulnerability Scanners ──
        ["nuclei"]="Template-based vuln scanner (7000+ templates)"
        ["sqlmap"]="SQL injection scanner"
        ["dalfox"]="Advanced XSS scanner"
        ["ssrfmap"]="SSRF exploitation tool"
        # ── Port Scanning ──
        ["nmap"]="Network port scanner"
        ["naabu"]="Fast port scanner"
        ["masscan"]="Ultra-fast port scanner"
        # ── Secret Scanning ──
        ["trufflehog"]="Deep git secret detection"
        ["gitleaks"]="Git secret scanning"
        # ── Parameter Discovery ──
        ["arjun"]="HTTP parameter discovery"
        ["paramspider"]="Parameter mining from archives"
        ["x8"]="Hidden parameter discovery"
        # ── WAF / Tech ──
        ["wafw00f"]="WAF fingerprinting"
        ["whatweb"]="Technology fingerprinting"
        # ── Notifications ──
        ["notify"]="Finding notifications (Slack/Discord)"
        # ── System ──
        ["go"]="Go language (required for Go tools)"
        ["python3"]="Python 3 interpreter"
        ["pip3"]="Python package manager"
        ["git"]="Version control"
        ["curl"]="HTTP client"
        ["wget"]="HTTP downloader"
        ["jq"]="JSON processor"
        ["nmap"]="Network scanner"
        ["whois"]="WHOIS lookup"
        ["dig"]="DNS lookup"
    )

    local installed_count=0
    local missing_count=0

    # Group by category
    echo ""
    for tool_name in $(echo "${!TOOLS[@]}" | tr ' ' '\n' | sort); do
        desc="${TOOLS[${tool_name}]}"
        if is_installed "${tool_name}"; then
            echo -e "  ${CHECKMARK} ${BOLD}${tool_name}${NC}  ${DIM}— ${desc}${NC}"
            ((installed_count++))
        else
            echo -e "  ${CROSS} ${RED}${tool_name}${NC}  ${DIM}— ${desc}${NC}"
            ((missing_count++))
        fi
    done

    echo ""
    echo -e "  ${GREEN}${BOLD}Installed: ${installed_count}${NC}  |  ${RED}${BOLD}Missing: ${missing_count}${NC}  |  Total: $((installed_count + missing_count))"
    echo ""

    # Check wordlists
    header "Wordlists"
    if [[ -d "/usr/share/seclists" ]]; then
        echo -e "  ${CHECKMARK} SecLists installed at /usr/share/seclists"
    elif [[ -d "${HOME}/wordlists/SecLists" ]]; then
        echo -e "  ${CHECKMARK} SecLists installed at ${HOME}/wordlists/SecLists"
    else
        echo -e "  ${CROSS} SecLists not found"
    fi

    if [[ -d "/usr/share/wordlists" ]]; then
        echo -e "  ${CHECKMARK} System wordlists at /usr/share/wordlists"
    fi

    exit 0
}

# ═══════════════════════════════════════════════════════════════════════
#  INSTALLATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

install_system_deps() {
    header "System Dependencies"

    if is_debian_like; then
        info "Updating package lists..."
        sudo apt-get update -qq 2>>"${LOG_FILE}"

        local PKGS=(
            git curl wget jq unzip build-essential
            python3 python3-pip python3-venv python3-dev
            nmap whois dnsutils net-tools
            libxml2-dev libxslt1-dev zlib1g-dev
            libffi-dev libssl-dev
            chromium-browser  # for headless crawling
        )
        info "Installing system packages..."
        sudo apt-get install -y -qq "${PKGS[@]}" 2>>"${LOG_FILE}" || true

        # Install Ruby for whatweb
        sudo apt-get install -y -qq ruby ruby-dev 2>>"${LOG_FILE}" || true

    elif is_arch_like; then
        sudo pacman -Syu --noconfirm --quiet 2>>"${LOG_FILE}"
        sudo pacman -S --noconfirm --quiet \
            git curl wget jq unzip base-devel \
            python python-pip nmap whois bind-tools net-tools \
            ruby chromium \
            2>>"${LOG_FILE}" || true

    elif is_macos; then
        if ! is_installed brew; then
            info "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install git curl wget jq nmap whois python3 ruby 2>>"${LOG_FILE}" || true
    fi

    success "System dependencies installed" "system-deps"
}

install_go_tools() {
    ensure_go
    export PATH="/usr/local/go/bin:${GO_BIN}:${PATH}"

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "minimal" || "${CATEGORY}" == "recon" ]]; then
        header "Recon Tools (Go)"
        go_install "subfinder"    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        go_install "assetfinder"  "github.com/tomnomnom/assetfinder@latest"
        go_install "waybackurls"  "github.com/tomnomnom/waybackurls@latest"
        go_install "gau"          "github.com/lc/gau/v2/cmd/gau@latest"
        go_install "shuffledns"   "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"

        if [[ "${CATEGORY}" != "minimal" ]]; then
            go_install "puredns"  "github.com/d3mondev/puredns/v2@latest"
        fi
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "probing" ]]; then
        header "HTTP Probing Tools (Go)"
        go_install "httpx"        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        go_install "httprobe"     "github.com/tomnomnom/httprobe@latest"
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "minimal" || "${CATEGORY}" == "discovery" ]]; then
        header "Content Discovery Tools (Go)"
        go_install "ffuf"         "github.com/ffuf/ffuf/v2@latest"
        go_install "gobuster"     "github.com/OJ/gobuster/v3@latest"

        if [[ "${CATEGORY}" != "minimal" ]]; then
            header "Feroxbuster (Rust)"
            install_feroxbuster
        fi
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "minimal" || "${CATEGORY}" == "scanner" ]]; then
        header "Vulnerability Scanners (Go)"
        go_install "nuclei"       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        go_install "dalfox"       "github.com/hahwul/dalfox/v2@latest"
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "network" ]]; then
        header "Port Scanning Tools (Go)"
        go_install "naabu"        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "secrets" ]]; then
        header "Secret Scanning Tools (Go)"
        go_install "trufflehog"   "github.com/trufflesecurity/trufflehog/v3@latest"
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "params" ]]; then
        header "Parameter Discovery (Go)"
        go_install "x8"           "github.com/Sh1Yo/x8@latest" || true
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "crawler" ]]; then
        header "Crawler Tools (Go)"
        go_install "katana"       "github.com/projectdiscovery/katana/cmd/katana@latest"
        go_install "gospider"     "github.com/jaeles-project/gospider@latest"
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "utility" ]]; then
        header "Utility Tools (Go)"
        go_install "notify"       "github.com/projectdiscovery/notify/cmd/notify@latest"
        go_install "dnsx"         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        go_install "asnmap"       "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    fi
}

install_feroxbuster() {
    ((TOTAL_TOOLS++))
    if is_installed feroxbuster; then
        skip "feroxbuster" "feroxbuster"
        return 0
    fi

    info "Installing ${BOLD}feroxbuster${NC}..."
    if is_debian_like; then
        # Try apt first (available on Kali)
        if sudo apt-get install -y -qq feroxbuster 2>>"${LOG_FILE}"; then
            success "feroxbuster installed via apt" "feroxbuster"
            return 0
        fi
    fi

    # Install from GitHub releases
    local ARCH
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64)  ARCH="x86_64" ;;
        aarch64) ARCH="aarch64" ;;
    esac

    local RELEASE_URL
    RELEASE_URL=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest | \
        jq -r ".assets[] | select(.name | contains(\"${ARCH}\") and contains(\"linux\")) | .browser_download_url" | head -1)

    if [[ -n "${RELEASE_URL}" ]]; then
        wget -q "${RELEASE_URL}" -O /tmp/feroxbuster.zip
        sudo unzip -o /tmp/feroxbuster.zip -d /usr/local/bin/ 2>>"${LOG_FILE}"
        sudo chmod +x /usr/local/bin/feroxbuster
        rm -f /tmp/feroxbuster.zip
        success "feroxbuster installed" "feroxbuster"
    else
        fail "Could not find feroxbuster release for ${ARCH}" "feroxbuster"
    fi
}

install_python_tools() {
    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "scanner" ]]; then
        header "Python-based Vulnerability Scanners"
        pip_install "sqlmap"
        pip_install "ssrfmap" "ssrfmap"
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "recon" ]]; then
        header "Python-based Recon Tools"
        pip_install "dnsrecon"
        pip_install "waymore"
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "params" ]]; then
        header "Python-based Parameter Tools"
        pip_install "arjun"
        pip_install "paramspider"
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "fingerprint" ]]; then
        header "Python-based Fingerprinting Tools"
        pip_install "wafw00f"
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "secrets" ]]; then
        header "Python-based Secret Scanners"
        pip_install "gitleaks" || true  # May be Go-based on some systems
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "discovery" ]]; then
        header "Python-based Discovery Tools"
        pip_install "dirsearch"
    fi
}

install_amass() {
    header "OWASP Amass"
    ((TOTAL_TOOLS++))

    if is_installed amass; then
        skip "amass" "amass"
        return 0
    fi

    info "Installing ${BOLD}amass${NC}..."
    local ARCH
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
    esac

    local AMASS_URL
    AMASS_URL=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest | \
        jq -r ".assets[] | select(.name | contains(\"linux_${ARCH}\")) | .browser_download_url" | head -1)

    if [[ -n "${AMASS_URL}" ]]; then
        wget -q "${AMASS_URL}" -O /tmp/amass.zip
        sudo unzip -o /tmp/amass.zip -d /tmp/amass_extract 2>>"${LOG_FILE}"
        sudo cp /tmp/amass_extract/*/amass /usr/local/bin/ 2>>"${LOG_FILE}" || \
            sudo find /tmp/amass_extract -name "amass" -type f -exec cp {} /usr/local/bin/ \;
        sudo chmod +x /usr/local/bin/amass
        rm -rf /tmp/amass.zip /tmp/amass_extract
        success "amass installed" "amass"
    else
        fail "Could not find amass release" "amass"
    fi
}

install_masscan() {
    header "Masscan (Ultra-fast Port Scanner)"
    ((TOTAL_TOOLS++))

    if is_installed masscan; then
        skip "masscan" "masscan"
        return 0
    fi

    info "Installing ${BOLD}masscan${NC}..."
    if is_debian_like; then
        if sudo apt-get install -y -qq masscan 2>>"${LOG_FILE}"; then
            success "masscan installed via apt" "masscan"
            return 0
        fi
    elif is_arch_like; then
        if sudo pacman -S --noconfirm masscan 2>>"${LOG_FILE}"; then
            success "masscan installed via pacman" "masscan"
            return 0
        fi
    elif is_macos; then
        if brew install masscan 2>>"${LOG_FILE}"; then
            success "masscan installed via brew" "masscan"
            return 0
        fi
    fi

    # Build from source
    info "Building masscan from source..."
    git clone --depth 1 https://github.com/robertdavidgraham/masscan.git /tmp/masscan 2>>"${LOG_FILE}"
    (cd /tmp/masscan && make -j"$(nproc)" 2>>"${LOG_FILE}" && sudo make install 2>>"${LOG_FILE}")
    rm -rf /tmp/masscan
    if is_installed masscan; then
        success "masscan built from source" "masscan"
    else
        fail "Failed to build masscan" "masscan"
    fi
}

install_massdns() {
    header "MassDNS (Bulk DNS Resolver)"
    ((TOTAL_TOOLS++))

    if is_installed massdns; then
        skip "massdns" "massdns"
        return 0
    fi

    info "Installing ${BOLD}massdns${NC} from source..."
    git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns 2>>"${LOG_FILE}"
    (cd /tmp/massdns && make -j"$(nproc)" 2>>"${LOG_FILE}" && sudo make install 2>>"${LOG_FILE}")
    rm -rf /tmp/massdns
    if is_installed massdns; then
        success "massdns built from source" "massdns"
    else
        fail "Failed to build massdns" "massdns"
    fi
}

install_gitleaks() {
    header "Gitleaks (Git Secret Scanner)"
    ((TOTAL_TOOLS++))

    if is_installed gitleaks; then
        skip "gitleaks" "gitleaks"
        return 0
    fi

    info "Installing ${BOLD}gitleaks${NC}..."
    local ARCH
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64)  ARCH="x64" ;;
        aarch64) ARCH="arm64" ;;
    esac

    local GIT_URL
    GIT_URL=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | \
        jq -r ".assets[] | select(.name | contains(\"linux\") and contains(\"${ARCH}\")) | .browser_download_url" | head -1)

    if [[ -n "${GIT_URL}" ]]; then
        wget -q "${GIT_URL}" -O /tmp/gitleaks.tar.gz
        sudo tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin/ gitleaks 2>>"${LOG_FILE}" || \
            (cd /tmp && tar -xzf gitleaks.tar.gz && sudo cp gitleaks /usr/local/bin/)
        sudo chmod +x /usr/local/bin/gitleaks
        rm -f /tmp/gitleaks.tar.gz
        success "gitleaks installed" "gitleaks"
    else
        fail "Could not find gitleaks release" "gitleaks"
    fi
}

install_findomain() {
    header "Findomain (Subdomain Monitor)"
    ((TOTAL_TOOLS++))

    if is_installed findomain; then
        skip "findomain" "findomain"
        return 0
    fi

    info "Installing ${BOLD}findomain${NC}..."
    local ARCH
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64)  ARCH="x86_64" ;;
        aarch64) ARCH="aarch64" ;;
    esac

    local FD_URL
    FD_URL=$(curl -s https://api.github.com/repos/Findomain/Findomain/releases/latest | \
        jq -r ".assets[] | select(.name | contains(\"linux\") and contains(\"${ARCH}\")) | .browser_download_url" | head -1)

    if [[ -n "${FD_URL}" ]]; then
        wget -q "${FD_URL}" -O /tmp/findomain.zip
        sudo unzip -o /tmp/findomain.zip -d /usr/local/bin/ 2>>"${LOG_FILE}" || true
        sudo chmod +x /usr/local/bin/findomain 2>/dev/null || true
        rm -f /tmp/findomain.zip
        if is_installed findomain; then
            success "findomain installed" "findomain"
        else
            fail "findomain binary not found after extraction" "findomain"
        fi
    else
        fail "Could not find findomain release" "findomain"
    fi
}

install_whatweb() {
    header "WhatWeb (Technology Fingerprinting)"
    ((TOTAL_TOOLS++))

    if is_installed whatweb; then
        skip "whatweb" "whatweb"
        return 0
    fi

    info "Installing ${BOLD}whatweb${NC}..."
    if is_debian_like; then
        if sudo apt-get install -y -qq whatweb 2>>"${LOG_FILE}"; then
            success "whatweb installed via apt" "whatweb"
            return 0
        fi
    fi

    # Install from source
    git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /tmp/whatweb 2>>"${LOG_FILE}"
    sudo cp /tmp/whatweb/whatweb /usr/local/bin/
    sudo chmod +x /usr/local/bin/whatweb
    rm -rf /tmp/whatweb
    if is_installed whatweb; then
        success "whatweb installed from source" "whatweb"
    else
        fail "Failed to install whatweb" "whatweb"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
#  WORDLISTS
# ═══════════════════════════════════════════════════════════════════════

install_wordlists() {
    if [[ "${CATEGORY}" != "all" && "${CATEGORY}" != "wordlists" ]]; then
        return 0
    fi

    header "Wordlists"

    # SecLists
    if [[ -d "/usr/share/seclists" || -d "${HOME}/wordlists/SecLists" ]]; then
        skip "SecLists" "seclists"
    else
        info "Cloning ${BOLD}SecLists${NC} (this may take a while)..."
        mkdir -p "${HOME}/wordlists"
        if git clone --depth 1 https://github.com/danielmiessler/SecLists.git "${HOME}/wordlists/SecLists" 2>>"${LOG_FILE}"; then
            sudo ln -sf "${HOME}/wordlists/SecLists" /usr/share/seclists 2>/dev/null || true
            success "SecLists installed" "seclists"
        else
            fail "Failed to clone SecLists" "seclists"
        fi
    fi

    # Assetnote Wordlists (smaller, curated)
    local ASSETNOTE_DIR="${HOME}/wordlists/assetnote"
    if [[ -d "${ASSETNOTE_DIR}" ]]; then
        skip "Assetnote wordlists" "assetnote-wordlists"
    else
        info "Downloading Assetnote best wordlists..."
        mkdir -p "${ASSETNOTE_DIR}"
        # Just grab the most useful ones
        for wl in "httparchive_subdomains_2024_05_28.txt" "httparchive_directories_1m_2024_05_28.txt" "httparchive_parameters_top_1m_2024_05_28.txt"; do
            wget -q "https://wordlists-cdn.assetnote.io/data/automated/${wl}" \
                -O "${ASSETNOTE_DIR}/${wl}" 2>>"${LOG_FILE}" || true
        done
        success "Assetnote wordlists downloaded" "assetnote-wordlists"
    fi

    # DNS resolver list for puredns/massdns
    local RESOLVERS="${HOME}/wordlists/resolvers.txt"
    if [[ -f "${RESOLVERS}" ]]; then
        skip "DNS resolvers list" "resolvers"
    else
        info "Downloading trusted DNS resolvers..."
        wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" \
            -O "${RESOLVERS}" 2>>"${LOG_FILE}" || true
        success "DNS resolvers list downloaded" "resolvers"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
#  NUCLEI TEMPLATES
# ═══════════════════════════════════════════════════════════════════════

install_nuclei_templates() {
    if [[ "${CATEGORY}" != "all" && "${CATEGORY}" != "scanner" && "${CATEGORY}" != "minimal" ]]; then
        return 0
    fi

    header "Nuclei Templates"

    if is_installed nuclei; then
        info "Updating nuclei templates..."
        nuclei -update-templates -silent 2>>"${LOG_FILE}" || true
        success "Nuclei templates updated" "nuclei-templates"
    else
        info "Nuclei not yet installed — templates will be fetched on first run"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
#  BBHUNTER PYTHON ENVIRONMENT
# ═══════════════════════════════════════════════════════════════════════

install_bbhunter() {
    header "BBHunter Python Environment"

    local PROJECT_DIR="${SCRIPT_DIR}"

    if [[ ! -f "${PROJECT_DIR}/pyproject.toml" ]]; then
        info "pyproject.toml not found in ${PROJECT_DIR} — skipping BBHunter install"
        return 0
    fi

    # Create venv if not exists
    if [[ ! -d "${PROJECT_DIR}/.venv" ]]; then
        info "Creating Python virtual environment..."
        python3 -m venv "${PROJECT_DIR}/.venv"
    fi

    info "Installing BBHunter and Python dependencies..."
    source "${PROJECT_DIR}/.venv/bin/activate"
    pip install --upgrade pip 2>>"${LOG_FILE}"

    if pip install -e "${PROJECT_DIR}" 2>>"${LOG_FILE}"; then
        success "BBHunter Python deps installed" "bbhunter-python"
    else
        # Try without optional deps
        pip install -e "${PROJECT_DIR}" --no-deps 2>>"${LOG_FILE}" || true
        pip install httpx dnspython beautifulsoup4 lxml pydantic pyyaml rich click \
            fastapi uvicorn sqlalchemy aiosqlite jinja2 pyjwt numpy 2>>"${LOG_FILE}" || true
        success "BBHunter core deps installed (some optional deps may be missing)" "bbhunter-python"
    fi

    deactivate 2>/dev/null || true
}

# ═══════════════════════════════════════════════════════════════════════
#  ENVIRONMENT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

configure_env() {
    header "Environment Configuration"

    # Ensure GO_BIN is on PATH
    export PATH="/usr/local/go/bin:${GO_BIN}:${HOME}/.local/bin:${PATH}"

    # Create .env template if not exists
    local ENV_FILE="${SCRIPT_DIR}/.env"
    if [[ ! -f "${ENV_FILE}" ]]; then
        info "Creating .env template..."
        cat > "${ENV_FILE}" << 'ENVEOF'
# ╔═══════════════════════════════════════════════════════╗
# ║  BBHunter Environment Variables                       ║
# ║  Fill in your API keys below                          ║
# ╚═══════════════════════════════════════════════════════╝

# GitHub (for code search recon)
GITHUB_TOKEN=

# Shodan
SHODAN_API_KEY=

# Censys
CENSYS_API_ID=
CENSYS_API_SECRET=

# VirusTotal
VIRUSTOTAL_API_KEY=

# SecurityTrails
SECURITYTRAILS_API_KEY=

# Subfinder Sources (optional, for premium sources)
# SUBFINDER_CONFIG=~/.config/subfinder/provider-config.yaml

# Notify (Discord/Slack/Telegram)
# Configure via: notify -provider-config ~/.config/notify/provider-config.yaml
ENVEOF
        success ".env template created — edit it with your API keys" "env-template"
    else
        skip ".env already exists" "env-template"
    fi

    # Create subfinder provider config directory
    mkdir -p "${HOME}/.config/subfinder" 2>/dev/null || true
    mkdir -p "${HOME}/.config/notify" 2>/dev/null || true

    # Ensure data directories
    mkdir -p "${SCRIPT_DIR}/data/models" "${SCRIPT_DIR}/data/reports" "${SCRIPT_DIR}/data/logs" 2>/dev/null || true
    success "Data directories created" "data-dirs"
}

# ═══════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════════════

print_summary() {
    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║              Installation Summary                             ║${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "  ${GREEN}${BOLD}Installed (${#INSTALLED[@]}):${NC}"
    for t in "${INSTALLED[@]}"; do
        echo -e "    ${CHECKMARK} ${t}"
    done

    if [[ ${#SKIPPED[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${YELLOW}${BOLD}Already installed (${#SKIPPED[@]}):${NC}"
        for t in "${SKIPPED[@]}"; do
            echo -e "    ${WARN} ${t}"
        done
    fi

    if [[ ${#FAILED[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${RED}${BOLD}Failed (${#FAILED[@]}):${NC}"
        for t in "${FAILED[@]}"; do
            echo -e "    ${CROSS} ${t}"
        done
    fi

    echo ""
    echo -e "  ${DIM}Log file: ${LOG_FILE}${NC}"
    echo ""

    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║              Next Steps                                       ║${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  1. ${BOLD}Edit your API keys:${NC}"
    echo -e "     ${DIM}nano ${SCRIPT_DIR}/.env${NC}"
    echo ""
    echo -e "  2. ${BOLD}Configure authorized targets:${NC}"
    echo -e "     ${DIM}nano ${SCRIPT_DIR}/authorized_targets.yaml${NC}"
    echo ""
    echo -e "  3. ${BOLD}Activate the virtual environment:${NC}"
    echo -e "     ${DIM}source ${SCRIPT_DIR}/.venv/bin/activate${NC}"
    echo ""
    echo -e "  4. ${BOLD}Run BBHunter:${NC}"
    echo -e "     ${DIM}bbhunter --help${NC}"
    echo -e "     ${DIM}bbhunter recon example.com${NC}"
    echo -e "     ${DIM}bbhunter dashboard${NC}"
    echo ""
    echo -e "  5. ${BOLD}Check tool status anytime:${NC}"
    echo -e "     ${DIM}./install_tools.sh --check${NC}"
    echo ""
    echo -e "  ${GREEN}${BOLD}Happy Hunting! 🎯${NC}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════

main() {
    banner

    # Check mode
    if [[ "${CATEGORY}" == "check" ]]; then
        check_status
    fi

    # Initialize log
    echo "BBHunter Tool Installation — $(date)" > "${LOG_FILE}"
    echo "Category: ${CATEGORY}" >> "${LOG_FILE}"
    echo "---" >> "${LOG_FILE}"

    detect_os

    header "Installation Plan: ${CATEGORY}"
    case "${CATEGORY}" in
        minimal)
            info "Installing CORE tools only: subfinder, httpx, nuclei, ffuf, nmap, sqlmap"
            ;;
        all)
            info "Installing ALL tools — full bug bounty toolkit"
            ;;
        *)
            info "Installing category: ${CATEGORY}"
            ;;
    esac

    # Run installations
    install_system_deps

    install_go_tools

    install_python_tools

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "recon" ]]; then
        install_amass
        install_findomain
        install_massdns
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "network" ]]; then
        install_masscan
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "secrets" ]]; then
        install_gitleaks
    fi

    if [[ "${CATEGORY}" == "all" || "${CATEGORY}" == "fingerprint" ]]; then
        install_whatweb
    fi

    install_wordlists
    install_nuclei_templates
    install_bbhunter
    configure_env

    print_summary
}

main "$@"
