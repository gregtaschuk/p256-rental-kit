#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# bind-real-card.sh — read the tapped card's P-256 public key via ACR122U
# and write it as JSON to a downstream consumer's cache file.
#
# This script is the lightweight alternative to `burn-card.sh --cap …`:
# burn-card.sh bundles the same caching step as its final phase after a full
# flash. Use bind-real-card.sh when the card is already burned and you just
# want to point a different consumer at it, or between burns while hacking.
#
# Usage:
#   BIND_CARD_CACHE_PATH=/path/to/.real-card.json ./scripts/bind-real-card.sh
#   ./scripts/bind-real-card.sh --clear       # delete the cache file
#
# The cache file is JSON: {"x":"0x<32-byte-hex>","y":"0x<32-byte-hex>"}.
#
# Prereqs: ACR122U connected, card on the reader, pcscd running, and
# `cd provisioner && npm install` run once.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Env / args ───────────────────────────────────────────────────────────────
CACHE_FILE="${BIND_CARD_CACHE_PATH:-}"

if [[ "${1:-}" == "--clear" ]]; then
  [[ -n "$CACHE_FILE" ]] || die "BIND_CARD_CACHE_PATH must be set to know which cache to clear."
  if [[ -f "$CACHE_FILE" ]]; then
    rm -f "$CACHE_FILE"
    success "Removed $CACHE_FILE"
  else
    info "No cache file at $CACHE_FILE to clear."
  fi
  exit 0
fi

[[ -n "$CACHE_FILE" ]] || die "BIND_CARD_CACHE_PATH must be set. Example: BIND_CARD_CACHE_PATH=/tmp/real-card.json $0"

# ── Read the card via the provisioner CLI ────────────────────────────────────
info "Reading card public key via ACR122U..."
cd "$ROOT/provisioner"

if [[ ! -d node_modules ]]; then
  info "Provisioner deps not installed — running npm install..."
  npm install
fi

output="$(npx ts-node src/index.ts read-key 2>&1)" || {
  echo "$output" >&2
  die "read-key failed. Ensure the ACR122U is plugged in, a card is on the reader, and pcscd is running."
}

# read-key prints:
#   Public key X: 0x...
#   Public key Y: 0x...
x="$(echo "$output" | awk '/Public key X:/ {print $NF}')"
y="$(echo "$output" | awk '/Public key Y:/ {print $NF}')"

if [[ -z "$x" || -z "$y" ]]; then
  echo "$output" >&2
  die "Could not parse X/Y from read-key output. See above."
fi

# ── Write the cache file ─────────────────────────────────────────────────────
mkdir -p "$(dirname "$CACHE_FILE")"
cat > "$CACHE_FILE" <<EOF
{
  "x": "$x",
  "y": "$y"
}
EOF

success "Cached real card key to: $CACHE_FILE"
echo "    X: $x"
echo "    Y: $y"
echo ""
info "The downstream consumer that reads this file will now bind to this card."
info "To forget the card later: BIND_CARD_CACHE_PATH=$CACHE_FILE $0 --clear"
