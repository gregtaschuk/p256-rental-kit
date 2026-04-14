# Tool Rental — Card Provisioner

CLI for setting up NFC JavaCards (J3R180 JCOP4-180K) and registering them on-chain.
Uses an ACR122U USB reader to communicate with the card over PC/SC.

---

## Card lifecycle

Each physical tool carries one JavaCard. The card holds a secp256k1 key pair generated
on first install — the private key never leaves the card. Its Ethereum address is the
identifier that ties the physical object to the on-chain NFT.

```
┌─────────────────────────────────────────────────────────────────────┐
│  ONE-TIME SETUP (provisioner + laptop)                              │
│                                                                     │
│  1. Build & load applet onto blank card (gp-tool)                   │
│  2. Read card's public key → derive Ethereum address                │
│  3. Mint ToolNFT on-chain, passing card address as constructor arg  │
│     → tokenId is the tool's permanent on-chain identifier           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │  card is attached to the tool (e.g. embedded in case)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  RENTAL START (borrower taps card with phone)                       │
│                                                                     │
│  1. Backend issues random 32-byte challenge                         │
│  2. Challenge submitted on-chain (5-min TTL)                        │
│  3. Phone sends hash to card via ISO 7816 APDU (INS 0x02)           │
│     hash = keccak256(toolId, "start", challenge, chainId, escrow)   │
│  4. Card signs hash with its private key → returns r, s (64 bytes)  │
│  5. Phone computes recovery bit v by trying both IDs                │
│  6. startRental(tokenId, days, challenge, v, r, s) called on-chain  │
│     → ecrecover must match cardAddressOf(tokenId)                   │
│     → borrower's rentalFee + deposit locked in escrow               │
└──────────────────────────────┬──────────────────────────────────────┘
                               │  tool is with the borrower
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  RENTAL END — clean return (lender taps card with phone)            │
│                                                                     │
│  1. Backend issues new challenge                                    │
│  2. Challenge submitted on-chain                                    │
│  3. Same tap flow as start, but:                                    │
│     hash = keccak256(rentalId, "end", challenge, chainId, escrow)   │
│  4. endRental(rentalId, challenge, v, r, s) called on-chain         │
│     → lender receives rentalFee                                     │
│     → borrower receives deposit back                                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │  tool returned to lender
```

**Alternative endings** (no card tap required):

| Scenario | Mechanism |
|---|---|
| Tool not returned by `deadline + gracePeriod` | Lender calls `claimDefault()` — receives everything |
| Card lost or destroyed | Either party calls `resolveByMutualConsent()` — requires both to consent; lender gets rentalFee, borrower gets deposit |
| Card lost, lender replaces it | Borrower approves in-app, lender calls `emergencyReplaceCard(rentalId, newCardAddress)` — rental continues with new card |

---

## APDU reference

The applet AID is `A0 00 00 06 17 00 01`.

| INS | Command | Input | Output |
|---|---|---|---|
| `0x01` | `GET_PUBLIC_KEY` | — | 64 bytes: X \|\| Y (no `0x04` prefix) |
| `0x02` | `SIGN` | 32-byte hash | 64 bytes: r \|\| s (raw, DER decoded on-card) |

> **SHA-256 note**: the applet uses `ALG_ECDSA_SHA_256`, which means the card
> applies SHA-256 to the input before signing. The hash sent to the card is
> `keccak256(...)`, so the card actually signs `SHA256(keccak256(...))`. The
> Solidity verifier must call `ecrecover` with the same pre-image: pass
> `sha256(keccak256(...))` as the digest, not the raw keccak256. Both sides
> must be consistent.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Node.js 18+ | |
| ACR122U USB reader | Connected before running any command |
| `pcsc-lite` | Linux: `sudo apt install pcscd` then `sudo systemctl start pcscd` |
| J3R180 JCOP4 card | Fresh from NXP (default GP keys) or with known custom keys |
| Java 11 + Maven | Only needed to build the applet from source |
| `gp.jar` (GlobalPlatformPro) | Only needed to load the applet onto the card |

---

## Automated burn (recommended)

Run `burn-card.sh` to build (if needed) and load the applet in one step.
Connect the ACR122U and place a blank card on it first.

```bash
cd provisioner

# With JAVACARD_SDK set — builds from source then burns:
export JAVACARD_SDK=/path/to/java_card_kit-3_0_5-rr-bin-do-linux-amd64
./burn-card.sh

# With a pre-built CAP (skip the Maven build):
./burn-card.sh --cap ../javacard/target/tool-rental-applet-1.0.0.cap

# Non-default GlobalPlatform keys (only for non-NXP-dev cards):
./burn-card.sh --gp-key ENC_HEX:MAC_HEX:DEK_HEX

# Preview all commands without executing:
./burn-card.sh --dry-run
```

The script downloads `gp.jar` automatically on first run if not already present.
It does **not** fuse or lock the card — default NXP GP keys are left intact so
the card can be re-provisioned if needed.

After the burn completes, run the `provision` command (step 3 below) to register
the card on-chain.

---

## Manual card setup

### 1. Build the applet

```bash
cd ../javacard
export JAVACARD_SDK=/path/to/java_card_kit-3_0_5-rr-bin-do-linux-amd64
mvn package
# → target/tool-rental-applet-1.0.0.cap
```

The Java Card 3.0.5 SDK is a free download from Oracle (registration required).

### 2. Load the applet onto the card

```bash
# Download gp-tool (single jar, no install)
wget https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar

# Verify the reader and card are visible
java -jar gp.jar --list

# Load and install the applet (works with default NXP test keys)
java -jar gp.jar --install ../javacard/target/tool-rental-applet-1.0.0.cap

# Confirm installation
java -jar gp.jar --list
# Should show AID A0000006170001 in the applet list
```

If your cards have non-default GlobalPlatform keys, pass them with `--key` or `--enc`,
`--mac`, `--dek` flags — see `java -jar gp.jar --help`.

### 3. Provision the card (mint ToolNFT on-chain)

```bash
cd ../provisioner && npm install

# With the local dev node running:
RPC_URL=http://127.0.0.1:8545 \
TOOLNFT_ADDRESS=<from dev-setup output> \
PRIVATE_KEY=<contract owner key> \
npx ts-node src/index.ts provision --owner <lender-wallet-address>
```

This reads the card's public key, derives its Ethereum address, and mints a ToolNFT
assigning that address as the card authenticator on-chain. The output tokenId is the
tool's permanent identifier in the system.

After provisioning the lender must approve the escrow contract once in the mobile app
(Settings → Approve Escrow), or call `toolNft.setApprovalForAll(escrowAddress, true)`
directly before listing.

---

## Utility commands

```bash
# Read public key and Ethereum address without minting
npx ts-node src/index.ts read-key

# Sign a test hash to verify the card is working
npx ts-node src/index.ts sign-test
```

---

## Card replacement

If a card is lost or damaged during an active rental:

1. **Both parties agree** — use Cooperative Close in the mobile app (no card needed).
2. **Card is physically replaced** — the borrower approves in-app, then the lender runs:

```bash
# Not a provisioner command — call the contract directly or use the mobile app
# emergencyReplaceCard(rentalId, newCardAddress)
```

To register a replacement card address outside of an active rental, the lender calls
`ToolNFT.replaceCard(tokenId, newCardAddress)` — only the token owner can do this, and
the old card loses signing authority immediately.
