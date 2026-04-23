# p256-rental-kit

Hardware-bound P-256 identity for Ethereum. A JavaCard applet that signs challenges with a secure-element P-256 key, plus an ACR122U provisioner CLI that flashes blank cards and mints on-chain NFTs bound to each card's public key. Designed for peer-to-peer protocols where a physical tap is the authorization gesture — rentals, handoffs, proofs of possession — and the on-chain counterparty verifies signatures via EIP-7212 (`P256.verify` at `0x100`) instead of trusting an off-chain witness.

## What's in here

```
javacard/     JavaCard applet (Maven + ant-javacard, JDK 11, Oracle JC 3.0.5 SDK)
              - ToolRentalApplet : core signer at AID A0000006170001
              - NdefApplet       : Type 4 NDEF tag at AID D2760000850101
provisioner/  Node.js CLI (TypeScript) for ACR122U USB NFC readers
              - burn-card.sh     : flash both CAPs onto a blank card via GlobalPlatform
              - src/index.ts     : read-key, provision (mint NFT), sign-test CLIs
scripts/
  bind-real-card.sh   : read the tapped card's (x, y) and write to a consumer cache file
```

## Applet surface

Two applets are installed on every card.

**Core signer** — `AID A0000006170001`

| INS | Command | Input | P1/P2 | Output |
|------|---------|-------|-------|--------|
| 0x01 | GET_PUBLIC_KEY | — | 00/00 | 64 bytes (X ‖ Y) |
| 0x02 | SIGN | 32-byte hash | P1=01 compute+store rentalId · P2=01 clear rentalId | 72 bytes (r[32] ‖ s[32] ‖ counter[8]) |
| 0x03 | GET_COUNTER | — | 00/00 | 8 bytes big-endian |
| 0x04 | GET_RENTAL_ID | — | 00/00 | 32 bytes (sha256, all zeros = none active) |

The card uses its hardware P-256 accelerator (`ALG_ECDSA_SHA_256`), so the input hash is SHA-256'd again internally before signing — both sides must account for that. Signatures are raw 64-byte `(r, s)`; DER-to-raw conversion happens inside the applet.

**NDEF Type 4 tag** — `AID D2760000850101`

Emits three NDEF records on a passive read:

1. `https://<your-domain>/tools/<cardKeyHash>` — works with iPhone Core NFC which only surfaces well-formed URLs to apps
2. `toolrental://card/<cardKeyHash>` — custom-scheme URI (backward compat with older deep-link handlers)
3. `"Tool Rental Card"` — human-readable label fallback

`<cardKeyHash>` is `sha256(X ‖ Y)` computed on the applet at install time and cached.

> AID `A0000006170001` is in the unregistered range and should be swapped for a registered RID before mainnet production. `D2760000850101` is the standard NDEF Type 4 AID and is globally reserved.

## Build

Prereqs: JDK 11 (not 17), Oracle JavaCard 3.0.5 SDK, Maven, pcscd (for flashing), Node.js 18+ (for the provisioner). On Ubuntu 22.04+ the included installer handles all of it:

```bash
./scripts/install-prerequisites.sh
```

Then build the applet:

```bash
cd javacard
./build.sh
```

Produces two CAP files in `javacard/target/`:

- `tool-rental-applet-1.0.0.cap`
- `tool-rental-ndef-1.0.0.cap`

If you'd rather not install the SDK, every `v*` tag release on this repo ships both CAPs as GitHub Release assets — download and hand them to `burn-card.sh --cap …` directly.

### Build gotchas

- `JAVACARD_SDK` must point at the **kit root** (containing `lib/`, `bin/`, `api_export_files/`), not the `lib/` directory. `build.sh` auto-detects `~/oracle_javacard_sdks/jc305u4_kit` as a fallback.
- JDK 17 is rejected by ant-javacard. Override `JAVA_HOME` to point at an 11 install just for this build; don't change it globally.
- The Oracle SDK isn't on Maven Central. Get it from the community mirror:
  ```bash
  git clone https://github.com/martinpaljak/oracle_javacard_sdks.git ~/oracle_javacard_sdks
  ```

## Flash

Prereqs: ACR122U USB NFC reader, `pcscd` running (Linux) or WinSCard (Windows), a blank J3R180 JCOP4-180K card, Node.js + `cd provisioner && npm install`.

```bash
cd provisioner
./burn-card.sh           # flash both CAPs onto the card on the reader
```

`burn-card.sh` downloads [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) on first run, uploads both CAPs, installs the applets, and (unless `--skip-verify`) reads the card's public key back to confirm the install worked. Use `--help` for options (`--cap`, `--gp-key`, `--dry-run`, `--lock`, etc.).

### Read a key (no flash)

```bash
npx ts-node src/index.ts read-key
```

Prints the card's P-256 public key `(x, y)`.

### Provision (mint a ToolNFT bound to the card)

```bash
npx ts-node src/index.ts provision \
  --owner   0x<lender-address> \
  --rpc-url $RPC_URL \
  --toolnft $TOOLNFT_ADDRESS \
  --private-key $PRIVATE_KEY
```

Reads the card's key, signs a mint tx, emits the `(tokenId, cardKeyX, cardKeyY)` binding on-chain. ABI is inlined — no artifact import needed.

## Consuming this repo from another project

The kit is designed to drop into a downstream project that wants its own state bound to a specific card (e.g., for test/dev seeding). Set `BIND_CARD_CACHE_PATH` to a JSON file your project reads, and every successful `burn-card.sh` run will update it with the burned card's key:

```bash
# In the downstream project, after a burn:
BIND_CARD_CACHE_PATH=/path/to/your/.real-card.json \
  /path/to/p256-rental-kit/provisioner/burn-card.sh
```

Or without a full flash, just read and cache:

```bash
BIND_CARD_CACHE_PATH=/path/to/your/.real-card.json \
  /path/to/p256-rental-kit/scripts/bind-real-card.sh
```

Cache format is a plain object: `{"x":"0x<32-byte-hex>","y":"0x<32-byte-hex>"}`.

If `BIND_CARD_CACHE_PATH` is unset, both scripts work as standalone tools — no write happens.

## APDU + AID constants

Downstream consumers typically duplicate the AIDs and INS codes rather than importing this repo as a package. The values are stable:

```
APPLET_AID     = 0xA0, 0x00, 0x00, 0x06, 0x17, 0x00, 0x01   // core signer
NDEF_AID       = 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01   // NDEF Type 4
INS_GET_PUBKEY = 0x01
INS_SIGN       = 0x02
INS_GET_COUNTER   = 0x03
INS_GET_RENTAL_ID = 0x04
```

## Releases

Tags matching `v*` trigger a GitHub Actions workflow that builds both CAPs and attaches them as release assets. For most consumers that's the fastest path — no JavaCard SDK needed.

## License

MIT. See `LICENSE`.
