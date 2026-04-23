#!/usr/bin/env bash
# build.sh — one-command JavaCard applet build.
#
# Wraps `mvn package` with the two environment variables ant-javacard insists
# on so you don't have to remember them every time:
#
#   JAVA_HOME    → JDK 11 (auto-detected; JC 3.0.5 rejects JDK 17)
#   JAVACARD_SDK → kit root at ~/oracle_javacard_sdks/jc305u4_kit (override
#                  via JAVACARD_SDK env var if you want a different kit)
#
# Usage:
#   cd javacard
#   ./build.sh            # builds both CAPs into target/
#   ./build.sh clean      # forwards any extra args to mvn — e.g. `./build.sh clean package`
#
# The script is idempotent and leaves your shell's global JAVA_HOME alone.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Find JDK 11 ──────────────────────────────────────────────────────────────
# Same candidate list as provisioner/burn-card.sh; keep them in sync if you
# add new paths.
jdk11=""
for c in \
    "${JAVA11_HOME:-}" \
    /usr/lib/jvm/java-11-openjdk-amd64 \
    /usr/lib/jvm/java-1.11.0-openjdk-amd64 \
    /usr/lib/jvm/java-11-openjdk \
    /usr/lib/jvm/temurin-11-jdk-amd64; do
    if [[ -n "$c" && -x "$c/bin/javac" ]]; then
        jdk11="$c"
        break
    fi
done
if [[ -z "$jdk11" ]]; then
    die "JDK 11 is required for the JavaCard 3.0.5 build (ant-javacard rejects JDK 17).
Install with:
  sudo apt install openjdk-11-jdk
Or set JAVA11_HOME to your JDK 11 install root and re-run."
fi

# ── Resolve JAVACARD_SDK ─────────────────────────────────────────────────────
# Validates an explicit env var first; if it points at something that doesn't
# look like a kit, transparently falls back to the martinpaljak mirror at
# ~/oracle_javacard_sdks/jc305u4_kit. This is the normal case — people set
# JAVACARD_SDK once in ~/.bashrc then forget it, and the path may go stale
# if they move / rename the kit.

is_valid_sdk() {
    local p="$1"
    [[ -z "$p" ]] && return 1
    [[ -d "$p/api_export_files" ]] || return 1
    [[ -f "$p/lib/api_classic.jar" || -f "$p/lib/api_classic-3.0.5.jar" ]] || return 1
    return 0
}

DEFAULT_SDK="$HOME/oracle_javacard_sdks/jc305u4_kit"

if is_valid_sdk "${JAVACARD_SDK:-}"; then
    JAVACARD_SDK="${JAVACARD_SDK%/}"
elif is_valid_sdk "$DEFAULT_SDK"; then
    if [[ -n "${JAVACARD_SDK:-}" && "${JAVACARD_SDK:-}" != "$DEFAULT_SDK" ]]; then
        echo -e "${YELLOW}[WARN]${NC}  Ignoring stale JAVACARD_SDK=${JAVACARD_SDK}"
        echo -e "${YELLOW}[WARN]${NC}  Falling back to default: $DEFAULT_SDK"
    fi
    JAVACARD_SDK="$DEFAULT_SDK"
else
    die "No usable Java Card 3.0.5 kit found.
Tried: ${JAVACARD_SDK:-<unset>}, $DEFAULT_SDK
Expected layout:
  <kit>/lib/api_classic.jar
  <kit>/api_export_files/
  <kit>/bin/
Get a properly-structured kit with:
  git clone https://github.com/martinpaljak/oracle_javacard_sdks ~/oracle_javacard_sdks"
fi

# ── Run Maven ────────────────────────────────────────────────────────────────
info "JDK 11: $jdk11"
info "JAVACARD_SDK: $JAVACARD_SDK"
info "Running: mvn ${*:-package}"
echo ""

cd "$SCRIPT_DIR"
env JAVA_HOME="$jdk11" PATH="$jdk11/bin:$PATH" JAVACARD_SDK="$JAVACARD_SDK" \
    mvn "${@:-package}"

echo ""
# Only print the summary if we built (don't spam after `clean`).
if [[ "${1:-package}" == "package" || "${1:-}" == "" ]]; then
    ls -lh target/*.cap 2>/dev/null && success "CAP files ready."
fi
