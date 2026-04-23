#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# install-prerequisites.sh — idempotent setup for building the JavaCard applet
# and running the ACR122U provisioner on Ubuntu 22.04+.
#
# Installs:
#   - System packages (git, git-lfs, maven, pcscd, libpcsclite-dev, nodejs)
#   - OpenJDK 11 (JavaCard 3.0.5 SDK rejects JDK 17)
#   - Oracle JavaCard Classic SDK 3.0.5 via the martinpaljak community mirror
#   - Provisioner npm dependencies
#
# What it does NOT do:
#   - Install the ACR122U USB driver (plug-and-play via pcsc-lite once the
#     daemon is running)
#   - Build JCMathLib — the jar is vendored at `javacard/lib/jcmathlib.jar`,
#     already committed. Only run ./scripts/rebuild-jcmathlib.sh if you need
#     to update it.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
skip()    { echo -e "${GREEN}[SKIP]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
section() { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
JCOP4_SDK_INSTALL_DIR="$HOME/oracle_javacard_sdks"
JCOP4_SDK_JAR="api_classic-3.0.5.jar"
JCMATHLIB_JAR_PATH="$REPO_ROOT/javacard/lib/jcmathlib.jar"

shell_rc() {
  if [[ "${SHELL:-}" == */zsh ]]; then echo "$HOME/.zshrc"; else echo "$HOME/.bashrc"; fi
}

append_to_rc() {
  local marker="$1" block="$2" rc
  rc="$(shell_rc)"
  if ! grep -qF "$marker" "$rc" 2>/dev/null; then
    printf '\n%s\n' "$block" >> "$rc"
    info "Added to $(shell_rc): $marker"
  fi
}

apt_installed() { dpkg -s "$1" &>/dev/null; }

require_non_root() {
  [[ "$EUID" -ne 0 ]] || { error "Do not run as root. sudo is invoked where needed."; exit 1; }
}

# ── 1. System packages ────────────────────────────────────────────────────────
install_system_packages() {
  section "System packages"
  local packages=(
    build-essential curl git git-lfs unzip jq
    pcscd libpcsclite-dev libpcsclite1 pcsc-tools
    openjdk-11-jdk maven
  )
  local missing=()
  for pkg in "${packages[@]}"; do
    apt_installed "$pkg" || missing+=("$pkg")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    skip "All system packages already installed."
    return
  fi
  info "Packages to install: ${missing[*]}"
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends "${missing[@]}"
  success "System packages installed."
}

# ── 2. Node.js ────────────────────────────────────────────────────────────────
#
# Only required for the provisioner CLI (TypeScript/ts-node). We use whatever
# Node is on PATH; any 18+ version works. If the user already has nvm, we leave
# it alone. Otherwise we install from NodeSource (no nvm assumption).
install_node() {
  section "Node.js"
  if command -v node &>/dev/null; then
    local v
    v="$(node --version)"
    success "node already installed: $v"
    return
  fi
  info "Installing Node.js 22 from NodeSource..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt-get install -y nodejs
  success "node installed: $(node --version)"
}

# ── 3. Java 11 (JAVA_HOME) ────────────────────────────────────────────────────
#
# ant-javacard (invoked from pom.xml) rejects JDK 17 with an explicit error.
# We export JAVA_HOME so `mvn package` picks it up without a per-command
# override.
configure_java() {
  section "OpenJDK 11"
  local java11
  for candidate in \
      "/usr/lib/jvm/java-11-openjdk-amd64" \
      "/usr/lib/jvm/java-11-openjdk" \
      "/usr/lib/jvm/java-11"; do
    [[ -x "$candidate/bin/java" ]] && { java11="$candidate"; break; }
  done
  [[ -n "${java11:-}" ]] || { error "openjdk-11-jdk not found after install. Check apt logs."; exit 1; }
  export JAVA_HOME="$java11"
  if ! grep -q '# JavaCard build — JDK 11' "$(shell_rc)" 2>/dev/null; then
    append_to_rc '# JavaCard build — JDK 11' \
"# JavaCard build — JDK 11 (ant-javacard rejects JDK 17)
export JAVA_HOME=${java11}
export PATH=\"\$JAVA_HOME/bin:\$PATH\""
  fi
  success "JAVA_HOME set to: ${java11}"
}

# ── 4. Oracle JavaCard Classic SDK 3.0.5 ─────────────────────────────────────
#
# The SDK is Oracle-licensed (OTN). The martinpaljak/oracle_javacard_sdks
# mirror repackages the official Oracle distributions with git-lfs — by
# downloading from there you accept the same terms as the official Oracle
# page: https://www.oracle.com/java/technologies/javacard-downloads.html
install_javacard_sdk() {
  section "Oracle JavaCard Classic SDK 3.0.5"

  # Already installed somewhere?
  local sdk_found=""
  for path in \
      "${JAVACARD_SDK:-}" \
      "$JCOP4_SDK_INSTALL_DIR/jc305u4_kit" \
      "$HOME/javacard-sdk-305" \
      "/opt/javacard-sdk-305"; do
    [[ -z "$path" ]] && continue
    if [[ -f "$path/lib/$JCOP4_SDK_JAR" && -d "$path/api_export_files" ]]; then
      sdk_found="$path"
      break
    fi
  done

  if [[ -z "$sdk_found" ]]; then
    info "Downloading from the martinpaljak/oracle_javacard_sdks mirror (git-lfs)..."
    echo ""
    echo -e "  ${YELLOW}License:${NC} Oracle OTN. By downloading via this mirror you accept"
    echo "           the same terms as the Oracle download page."
    echo ""
    git lfs install --skip-repo &>/dev/null || true
    if [[ -d "$JCOP4_SDK_INSTALL_DIR/.git" ]]; then
      (cd "$JCOP4_SDK_INSTALL_DIR" && git pull --quiet)
    else
      rm -rf "$JCOP4_SDK_INSTALL_DIR"
      git clone --depth 1 https://github.com/martinpaljak/oracle_javacard_sdks "$JCOP4_SDK_INSTALL_DIR"
    fi
    sdk_found="$JCOP4_SDK_INSTALL_DIR/jc305u4_kit"
    [[ -f "$sdk_found/lib/$JCOP4_SDK_JAR" ]] || {
      error "SDK jar not found after clone. If every file is ~130 bytes, run:"
      error "  cd $JCOP4_SDK_INSTALL_DIR && git lfs pull"
      exit 1
    }
  fi

  export JAVACARD_SDK="$sdk_found"
  if ! grep -q 'JAVACARD_SDK' "$(shell_rc)" 2>/dev/null; then
    append_to_rc 'JAVACARD_SDK' \
"# Oracle JavaCard Classic SDK 3.0.5 (kit root, not lib/)
export JAVACARD_SDK=${sdk_found}"
  fi
  success "JAVACARD_SDK set to: ${sdk_found}"
}

# ── 5. PC/SC daemon (ACR122U) ─────────────────────────────────────────────────
configure_pcscd() {
  section "PC/SC daemon"
  sudo systemctl enable pcscd --quiet
  sudo systemctl start pcscd 2>/dev/null || true
  success "pcscd enabled. Plug in the ACR122U and verify with: pcsc_scan"
  if getent group pcscd &>/dev/null && ! id -nG "$USER" | grep -qw pcscd; then
    sudo usermod -aG pcscd "$USER"
    info "Added $USER to pcscd group — re-login for group change to take effect."
  fi
}

# ── 6. JCMathLib jar (pre-vendored) ───────────────────────────────────────────
check_jcmathlib() {
  section "JCMathLib jar"
  if [[ -f "$JCMATHLIB_JAR_PATH" ]]; then
    success "Vendored jar found at: $JCMATHLIB_JAR_PATH"
  else
    warn "Vendored jar missing at $JCMATHLIB_JAR_PATH — the build will fail."
    warn "Re-checkout the jar (it's committed), or build from OpenCryptoProject/JCMathLib."
  fi
}

# ── 7. Provisioner npm install ────────────────────────────────────────────────
install_provisioner_deps() {
  section "Provisioner npm dependencies"
  if [[ -d "$REPO_ROOT/provisioner/node_modules" ]]; then
    skip "provisioner/node_modules already present — run 'npm install' there manually to refresh."
    return
  fi
  (cd "$REPO_ROOT/provisioner" && npm install)
  success "Provisioner deps installed."
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  echo -e "${BOLD}"
  echo "╔═══════════════════════════════════════════════╗"
  echo "║  p256-rental-kit — Prerequisites Installer    ║"
  echo "║  Target: Ubuntu 22.04+  (idempotent)          ║"
  echo "╚═══════════════════════════════════════════════╝"
  echo -e "${NC}"

  require_non_root
  install_system_packages
  install_node
  configure_java
  install_javacard_sdk
  configure_pcscd
  check_jcmathlib
  install_provisioner_deps

  echo ""
  success "Prerequisites installed."
  echo ""
  info "Next steps:"
  echo "  - Restart your shell (or 'source $(shell_rc)') to pick up JAVA_HOME/JAVACARD_SDK."
  echo "  - Build the CAPs:   cd javacard && ./build.sh"
  echo "  - Flash a card:     cd provisioner && ./burn-card.sh"
}

main "$@"
