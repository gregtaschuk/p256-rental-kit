#!/usr/bin/env bash
# test-card.sh — Run the full verification suite against a burned ToolRental
# JavaCard. Confirms the applet is installed, its on-card P-256 key is
# well-formed, signs a test hash, and verifies the signature with the same
# SHA-256 preprocessing the RentalEscrow contract uses.
#
# Usage:
#   ./test-card.sh           # run verification
#   ./test-card.sh --dry-run # print the command without touching the card
#   ./test-card.sh -h        # help
#
# Exits 0 on all-green, 1 if any check fails or the card isn't responding.
#
# Prereqs: ACR122U connected, card on the reader, pcscd running, provisioner
# deps installed (`cd provisioner && npm install`).

set -euo pipefail

# ── Colour helpers (copied from burn-card.sh for independence) ───────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Args ─────────────────────────────────────────────────────────────────────

DRY_RUN=0
usage() {
    sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1. Use --help for usage." ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Prereqs ──────────────────────────────────────────────────────────────────

info "Checking prerequisites..."

command -v node >/dev/null 2>&1 || die "node not found in PATH. Install Node.js."
command -v npx >/dev/null 2>&1 || die "npx not found in PATH (ships with npm)."

if [[ "$(uname -s)" == "Linux" ]]; then
    # pcscd on Ubuntu is socket-activated — pcscd.service is "inactive"
    # until a client opens the socket. Accept either unit being active.
    if systemctl is-active --quiet pcscd.service 2>/dev/null \
            || systemctl is-active --quiet pcscd.socket 2>/dev/null; then
        success "pcscd is running."
    else
        if [[ "$DRY_RUN" -eq 1 ]]; then
            warn "pcscd is not running (OK in --dry-run)"
        else
            die "pcscd is not running. Enable it permanently with:
  sudo systemctl enable --now pcscd.socket pcscd.service
Then re-run this script."
        fi
    fi
fi

if [[ ! -d "$SCRIPT_DIR/node_modules" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
        warn "Provisioner deps not installed (OK in --dry-run)"
    else
        info "Provisioner deps not installed — running npm install..."
        (cd "$SCRIPT_DIR" && npm install)
    fi
fi

# ── Run verify ───────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Tool Rental — card verification${NC}"
echo ""

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} (cd $SCRIPT_DIR && npx ts-node src/index.ts verify)"
    exit 0
fi

# Forward the CLI's exit code so callers can chain on success/failure.
(cd "$SCRIPT_DIR" && npx ts-node src/index.ts verify)
