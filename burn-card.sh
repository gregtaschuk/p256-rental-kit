#!/usr/bin/env bash
# burn-card.sh — Load the ToolRental JavaCard applet onto a blank J3R180 JCOP4-180K card.
#
# Loads (does NOT fuse/lock) the applet — card remains re-provisionable with default NXP keys.
#
# Usage:
#   ./burn-card.sh [options]
#
# Options:
#   --cap <path>              Use a pre-built .cap file instead of building from source
#   --gp-jar <path>           Path to gp.jar (default: ./gp.jar; auto-downloaded if absent)
#   --gp-key <enc:mac:dek>    Non-default GlobalPlatform secure channel keys (hex, colon-sep)
#   --skip-verify             Skip the post-install sign/verify round-trip (see ./test-card.sh)
#   -y, --yes                 Auto-confirm re-burn if applets are already installed
#   --dry-run                 Print commands without executing
#   -h, --help                Show this help
#
# Prerequisites:
#   - java 11+ in PATH
#   - ACR122U reader connected
#   - Card placed on reader before running
#   - pcscd running (Linux: sudo systemctl start pcscd)
#   - curl or wget (only if gp.jar needs to be downloaded)
#
# To build the applet from source, set JAVACARD_SDK to your Java Card 3.0.5 SDK directory:
#   export JAVACARD_SDK=/path/to/java_card_kit-3_0_5-rr-bin-do-linux-amd64
#
# After a successful burn, run:
#   npx ts-node src/index.ts provision --owner <lender-wallet-address>

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAVACARD_DIR="$(cd "$SCRIPT_DIR/../javacard" && pwd)"

GP_VERSION="25.10.20"
GP_DOWNLOAD_URL="https://github.com/martinpaljak/GlobalPlatformPro/releases/download/v${GP_VERSION}/gp.jar"
GP_JAR_DEFAULT="$SCRIPT_DIR/gp.jar"
CAP_DEFAULT="$JAVACARD_DIR/target/tool-rental-applet-1.0.0.cap"
NDEF_CAP_DEFAULT="$JAVACARD_DIR/target/tool-rental-ndef-1.0.0.cap"
APPLET_AID="A0000006170001"
NDEF_AID="D2760000850101"

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

# ── Argument parsing ──────────────────────────────────────────────────────────

CAP_FILE=""
GP_JAR=""
GP_KEY=""
DRY_RUN=0
SKIP_VERIFY=0
ASSUME_YES=0

usage() {
    sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cap)         CAP_FILE="$2"; shift 2 ;;
        --gp-jar)      GP_JAR="$2";   shift 2 ;;
        --gp-key)      GP_KEY="$2";   shift 2 ;;
        --dry-run)     DRY_RUN=1;     shift   ;;
        --skip-verify) SKIP_VERIFY=1; shift   ;;
        -y|--yes)      ASSUME_YES=1;  shift   ;;
        -h|--help)     usage; exit 0           ;;
        *)             die "Unknown option: $1. Use --help for usage." ;;
    esac
done

GP_JAR="${GP_JAR:-$GP_JAR_DEFAULT}"

# Strip trailing slash from JAVACARD_SDK if set (prevents broken systemPath in pom.xml)
if [[ -n "${JAVACARD_SDK:-}" ]]; then
    JAVACARD_SDK="${JAVACARD_SDK%/}"
    export JAVACARD_SDK
fi

# ── Dry-run wrapper ───────────────────────────────────────────────────────────

run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $*"
    else
        "$@"
    fi
}

# ── Build the gp.jar base command array ──────────────────────────────────────
# Populated after ensure_gp_jar() so GP_JAR is resolved.
# GP_KEY is "ENC:MAC:DEK" (colons); gp.jar expects "--key ENC/MAC/DEK" (slashes).

build_gp_cmd() {
    GP_CMD=(java -jar "$GP_JAR")
    if [[ -n "$GP_KEY" ]]; then
        local key_slashes="${GP_KEY//:///}"
        GP_CMD+=(--key "$key_slashes")
    fi
}

# ── Step 1: Check prerequisites ───────────────────────────────────────────────

check_prerequisites() {
    info "Checking prerequisites..."

    command -v java &>/dev/null || die "java not found in PATH. Install Java 11+."

    local java_ver
    java_ver=$(java -version 2>&1 | awk -F'"' '/version/ {print $2}' | cut -d. -f1)
    # Handle "1.x" legacy versioning (Java 8 would be "1") and modern "11", "17", "21"
    if [[ "$java_ver" == "1" ]]; then
        die "Java 11+ required. Found Java 8 or earlier."
    elif [[ "$java_ver" =~ ^[0-9]+$ ]] && [[ "$java_ver" -lt 11 ]]; then
        die "Java 11+ required. Found Java $java_ver."
    fi
    success "Java $java_ver detected."

    if [[ "$(uname -s)" == "Linux" ]]; then
        # Ubuntu ships pcscd as socket-activated: pcscd.service is "inactive"
        # until a client opens /run/pcscd/pcscd.comm, at which point systemd
        # spawns the daemon on demand. Accept either the service OR the socket
        # being active — either one means we can talk to it.
        if systemctl is-active --quiet pcscd.service 2>/dev/null \
                || systemctl is-active --quiet pcscd.socket 2>/dev/null; then
            success "pcscd is running."
        else
            local msg="pcscd is not running. Enable it permanently with:
  sudo systemctl enable --now pcscd.socket pcscd.service
Or just start it for this session:
  sudo systemctl start pcscd.socket"
            if [[ "$DRY_RUN" -eq 1 ]]; then
                warn "$msg"
            else
                die "$msg
Then re-run this script."
            fi
        fi
    fi
}

# ── Step 2: Locate or download gp.jar ────────────────────────────────────────

ensure_gp_jar() {
    if [[ -f "$GP_JAR" ]]; then
        info "Using gp.jar: $GP_JAR"
        return
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        warn "gp.jar not found at $GP_JAR (would auto-download in a real run)"
        return
    fi

    info "gp.jar not found. Downloading v${GP_VERSION} from GitHub..."
    if command -v curl &>/dev/null; then
        curl -fsSL -o "$GP_JAR" "$GP_DOWNLOAD_URL"
    elif command -v wget &>/dev/null; then
        wget -q -O "$GP_JAR" "$GP_DOWNLOAD_URL"
    else
        die "Neither curl nor wget found. Download gp.jar manually:
  $GP_DOWNLOAD_URL
Place it at: $GP_JAR"
    fi
    success "Downloaded gp.jar → $GP_JAR"
}

# ── Step 3: Resolve CAP file ──────────────────────────────────────────────────

resolve_cap_file() {
    if [[ -n "$CAP_FILE" ]]; then
        [[ -f "$CAP_FILE" ]] || die "CAP file not found: $CAP_FILE"
        info "Using pre-built CAP: $CAP_FILE"
        return
    fi

    if [[ -n "${JAVACARD_SDK:-}" ]]; then
        # Validate the SDK layout — ant-javacard rejects flat jar dumps with a
        # cryptic "No usable JavaCard SDK referenced" error. The kit's API jar
        # is named api_classic.jar (no version suffix); accept either name so
        # this works against any reasonable kit layout.
        if [[ ! -f "$JAVACARD_SDK/lib/api_classic.jar" && ! -f "$JAVACARD_SDK/lib/api_classic-3.0.5.jar" ]] \
            || [[ ! -d "$JAVACARD_SDK/api_export_files" ]]; then
            die "JAVACARD_SDK does not look like an Oracle Java Card 3.0.5 kit:
  $JAVACARD_SDK
Expected layout:
  \$JAVACARD_SDK/lib/api_classic.jar
  \$JAVACARD_SDK/api_export_files/
  \$JAVACARD_SDK/bin/
Get a properly-structured kit:
  git clone https://github.com/martinpaljak/oracle_javacard_sdks ~/oracle_javacard_sdks
  export JAVACARD_SDK=~/oracle_javacard_sdks/jc305u4_kit"
        fi

        # ant-javacard hard-rejects JDK 17 with JC 3.0.5. Find a JDK 11 to use
        # for the build, leaving the user's global JAVA_HOME (often 17, for
        # Android tooling) untouched.
        local jdk11=""
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

        info "JAVACARD_SDK is set. Building applet via javacard/build.sh..."
        # The wrapper handles JDK 11 selection + SDK fallback, so we don't
        # need to repeat that logic here. See javacard/build.sh.
        run "$JAVACARD_DIR/build.sh" -q package
        CAP_FILE="$CAP_DEFAULT"
        NDEF_CAP_FILE="$NDEF_CAP_DEFAULT"
    elif [[ -f "$CAP_DEFAULT" ]]; then
        info "Using existing CAP: $CAP_DEFAULT"
        CAP_FILE="$CAP_DEFAULT"
        NDEF_CAP_FILE="$NDEF_CAP_DEFAULT"
    else
        die "No CAP file available. Options:
  1. Pass --cap /path/to/tool-rental-applet-1.0.0.cap
  2. Set JAVACARD_SDK=/path/to/jc305_kit and re-run (builds via Maven)
  3. Copy a pre-built CAP to: $CAP_DEFAULT"
    fi

    if [[ "$DRY_RUN" -ne 1 && ! -f "$NDEF_CAP_FILE" ]]; then
        die "NDEF CAP file missing: $NDEF_CAP_FILE
This should have been built alongside the core CAP. Re-run with JAVACARD_SDK set."
    fi
}

# ── Step 4: Verify reader/card ────────────────────────────────────────────────

verify_reader_and_card() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} ${GP_CMD[*]} --list  # verify reader and card"
        echo ""
        return
    fi

    info "Checking reader and card visibility..."
    if ! "${GP_CMD[@]}" --list 2>&1; then
        die "gp.jar --list failed. Ensure:
  - ACR122U is connected via USB
  - Card is placed on the reader
  - pcscd is running: sudo systemctl start pcscd
If multiple readers are present, use --gp-jar and pass --reader <name> manually."
    fi
    echo ""
}

# ── Step 5: Install applet(s) ─────────────────────────────────────────────────

# install_one_cap <cap-path> <friendly-name>
# Installs a single CAP file. Dies on any failure — the pre-flight cleanup
# in install_applet() has already removed anything that would conflict.
install_one_cap() {
    local cap_file="$1"
    local friendly="$2"

    info "Installing ${friendly}..."
    info "CAP: $cap_file"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} ${GP_CMD[*]} --install $cap_file"
        return
    fi

    local output rc=0
    output=$("${GP_CMD[@]}" --install "$cap_file" 2>&1) || rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "$output" >&2
        die "gp.jar --install failed for ${friendly} (exit code $rc). See output above."
    fi

    echo "$output"
    success "${friendly} installed."
}

# uninstall_one_cap <cap-path> <friendly-name>
# Force-uninstall a single CAP. Dies on failure.
uninstall_one_cap() {
    local cap_file="$1"
    local friendly="$2"

    info "Uninstalling existing ${friendly}..."
    local output rc=0
    output=$("${GP_CMD[@]}" --uninstall "$cap_file" 2>&1) || rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "$output" >&2
        die "gp.jar --uninstall failed for ${friendly} (exit code $rc). See output above."
    fi
    success "Existing ${friendly} removed."
}

install_applet() {
    info "Loading and installing applets onto card..."
    echo ""

    # ── Pre-flight: detect existing installs ────────────────────────────
    # If either of our packages is already on the card, we must remove them
    # in REVERSE dependency order (NDEF first, then core) because the NDEF
    # package imports CardKeyShareable from the core package, and
    # GlobalPlatform refuses to delete a package that still has loaded
    # dependents.
    local have_core=0 have_ndef=0
    if [[ "$DRY_RUN" -ne 1 ]]; then
        local list_output
        list_output=$("${GP_CMD[@]}" --list 2>&1 || true)
        if echo "$list_output" | grep -qiE "PKG:[[:space:]]+A00000061700[[:space:]]"; then
            have_core=1
        fi
        if echo "$list_output" | grep -qiE "PKG:[[:space:]]+D2760000850100[[:space:]]"; then
            have_ndef=1
        fi
    fi

    if [[ $have_core -eq 1 || $have_ndef -eq 1 ]]; then
        warn "Tool Rental applet(s) already installed on this card:"
        [[ $have_core -eq 1 ]] && warn "  - core package (A00000061700)"
        [[ $have_ndef -eq 1 ]] && warn "  - NDEF package (D2760000850100)"
        warn ""
        warn "Re-burning will destroy the on-card P-256 key pair."
        warn "Any ToolNFT on-chain registration tied to it will need re-binding."
        echo ""
        if [[ "$ASSUME_YES" -eq 1 ]]; then
            info "--yes passed; proceeding with re-burn."
        else
            local reply=""
            read -r -p "Uninstall existing and re-install both? [y/N] " reply
            if [[ ! "$reply" =~ ^[Yy]$ ]]; then
                die "Aborted by user. Card unchanged."
            fi
        fi

        # Reverse dependency order: NDEF first, then core.
        [[ $have_ndef -eq 1 ]] && uninstall_one_cap "$NDEF_CAP_FILE" "NDEF tag applet"
        [[ $have_core -eq 1 ]] && uninstall_one_cap "$CAP_FILE"      "ToolRental core applet"
        echo ""
    fi

    # Forward dependency order: core first (generates the P-256 key), then
    # NDEF (reads that key via the Shareable interface at install time).
    install_one_cap "$CAP_FILE"      "ToolRental core applet"
    echo ""
    install_one_cap "$NDEF_CAP_FILE" "NDEF tag applet"
}

# ── Step 6: Confirm installation ──────────────────────────────────────────────

confirm_install() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} ${GP_CMD[*]} --list  # would check for AIDs $APPLET_AID and $NDEF_AID"
        return
    fi

    info "Confirming applet AIDs appear in card registry..."
    local list_output
    list_output=$("${GP_CMD[@]}" --list 2>&1)

    local ok=1
    if echo "$list_output" | grep -qi "$APPLET_AID"; then
        success "Core applet AID $APPLET_AID confirmed on card."
    else
        warn "Could not confirm core AID $APPLET_AID in --list output."
        ok=0
    fi
    if echo "$list_output" | grep -qi "$NDEF_AID"; then
        success "NDEF applet AID $NDEF_AID confirmed on card."
    else
        warn "Could not confirm NDEF AID $NDEF_AID in --list output."
        ok=0
    fi
    if [[ $ok -eq 0 ]]; then
        echo "$list_output"
        warn "The install may still have succeeded — check the output above manually."
    fi
}

# ── Step 7: Verify the burn end-to-end ────────────────────────────────────────

# Runs the `verify` CLI command (full sign/verify round-trip). We do this
# immediately after the install because the reader and card are already in
# hand — catching a bad burn in the same command is much more useful than
# discovering it later in the mobile app. Skippable via --skip-verify.
run_verify() {
    if [[ "$SKIP_VERIFY" -eq 1 ]]; then
        info "Skipping verification (--skip-verify)."
        return 0
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} (cd $SCRIPT_DIR && npx ts-node src/index.ts verify)"
        return 0
    fi

    echo ""
    info "Running card verification..."
    echo ""

    # Ensure provisioner deps are installed — verify needs @noble/curves.
    if [[ ! -d "$SCRIPT_DIR/node_modules" ]]; then
        info "Provisioner deps not installed — running npm install..."
        (cd "$SCRIPT_DIR" && npm install)
    fi

    if ! (cd "$SCRIPT_DIR" && npx ts-node src/index.ts verify); then
        die "Card verification failed. The applet may have installed without a working key pair.
Try re-burning, or run ./test-card.sh directly for more detail."
    fi
}

# ── Step 8: Success banner ────────────────────────────────────────────────────

print_success() {
    echo ""
    echo -e "${BOLD}${GREEN}Card burn complete and verified!${NC}"
    echo ""
    echo "Next step — provision the card (read public key + mint ToolNFT on-chain):"
    echo ""
    echo "  cd $SCRIPT_DIR"
    echo "  RPC_URL=http://127.0.0.1:8545 \\"
    echo "  TOOLNFT_ADDRESS=<from dev-setup output> \\"
    echo "  PRIVATE_KEY=<contract owner key> \\"
    echo "  npx ts-node src/index.ts provision --owner <lender-wallet-address>"
    echo ""
    echo "Re-run verification any time with:"
    echo "  ./test-card.sh"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    echo -e "${BOLD}Tool Rental — JavaCard Burn Script${NC}"
    echo ""

    check_prerequisites
    ensure_gp_jar
    resolve_cap_file

    [[ "$DRY_RUN" -eq 1 ]] || [[ -f "$CAP_FILE" ]] || \
        die "CAP file missing after resolution: $CAP_FILE"

    build_gp_cmd

    verify_reader_and_card
    install_applet
    confirm_install
    run_verify
    print_success
}

main "$@"
