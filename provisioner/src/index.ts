#!/usr/bin/env ts-node
// SPDX-License-Identifier: MIT
/**
 * Tool Rental Card Provisioner CLI
 *
 * Uses an ACR122U USB NFC reader to:
 *   provision  — Read the card's public key and mint a ToolNFT on-chain.
 *   read-key   — Just read and display the card's public key and Ethereum address.
 *   sign-test  — Sign a test hash and display the result (for debugging).
 *   verify     — Full sign/verify round-trip with pass/fail checks (for burns).
 *
 * Prerequisites:
 *   - ACR122U driver installed (pcsc-lite on Linux, WinSCard on Windows)
 *   - JAVACARD_CAP_FILE env var pointing to the compiled .cap applet file
 *   - TOOLNFT_ADDRESS env var with ToolNFT contract address
 *   - RPC_URL env var
 *   - PRIVATE_KEY env var (deployer / contract owner key for signing txs)
 *
 * Usage:
 *   npx ts-node src/index.ts provision --owner <lender-address>
 *   npx ts-node src/index.ts read-key
 *   npx ts-node src/index.ts sign-test
 */

import { NFC } from "nfc-pcsc";
import { Command } from "commander";
import { ethers } from "ethers";
import { p256 } from "@noble/curves/p256";
import { readCardPublicKey, readCardCounter, signHash, readRentalId } from "./card";
import { parseResponse } from "./apdu";

// Minimal ABI for ToolNFT (only the functions used by the provisioner)
const TOOLNFT_ABI = [
  "function mint(address to, bytes32 cardKeyX, bytes32 cardKeyY) external returns (uint256 tokenId)",
  "function ownerOf(uint256 tokenId) external view returns (address)",
  "function cardPublicKey(uint256 tokenId) external view returns (bytes32 x, bytes32 y)",
  "event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)",
];

const program = new Command();
program.name("provisioner").description("Tool Rental JavaCard provisioner (ACR122U)");

// ── read-key command ──────────────────────────────────────────────────────────

program
  .command("read-key")
  .description("Read the card's P-256 public key coordinates")
  .action(async () => {
    await withReader(async (reader) => {
      console.log("Reading card public key...");
      const { x, y } = await readCardPublicKey(reader);
      console.log("\nPublic key X:", x);
      console.log("Public key Y:", y);
    });
  });

// ── inspect command ──────────────────────────────────────────────────────────

program
  .command("inspect")
  .description("Read all card state in a single session (key, counter, rental ID, NDEF)")
  .action(async () => {
    await withReader(async (reader) => {
      // 1. Public key
      const { x, y } = await readCardPublicKey(reader);
      const cardKeyHash = ethers.sha256(ethers.concat([x, y])).slice(2);

      console.log("Public key X:", x);
      console.log("Public key Y:", y);
      console.log("Card key hash: 0x" + cardKeyHash);

      // 2. Counter
      try {
        const counter = await readCardCounter(reader);
        const used = counter > 1n ? Number(counter) - 1 : 0;
        console.log(`Counter: ${counter} (${used} signature${used === 1 ? "" : "s"} issued)`);
      } catch {
        console.log("Counter: (unsupported)");
      }

      // 3. Rental ID
      try {
        const rentalId = await readRentalId(reader);
        const isZero = rentalId === "0x" + "00".repeat(32);
        console.log(`Rental ID: ${isZero ? "(none — card is idle)" : rentalId}`);
      } catch {
        console.log("Rental ID: (unsupported)");
      }

      // 4. NDEF URIs (derived from key hash — matches what the NDEF applet emits)
      console.log("NDEF URIs:");
      console.log(`  toolrental://card/${cardKeyHash}`);
      console.log(`  https://pyrite.rocks/tools/${cardKeyHash}`);
    });
  });

// ── sign-test command ─────────────────────────────────────────────────────────

program
  .command("sign-test")
  .description("Sign a test hash and verify recovery")
  .action(async () => {
    await withReader(async (reader) => {
      const { x, y } = await readCardPublicKey(reader);
      console.log("Card public key X:", x);
      console.log("Card public key Y:", y);

      const testHash = ethers.id("test-message"); // keccak256("test-message")
      const hash32 = Buffer.from(testHash.slice(2), "hex");

      console.log("Signing hash:", testHash);
      const { r, s } = await signHash(reader, hash32);
      console.log("r:", r);
      console.log("s:", s);

      console.log("\nNote: Card applies SHA-256 to the input before signing.");
      console.log("For on-chain verification, ensure the hash construction matches.");
    });
  });

// ── verify command ────────────────────────────────────────────────────────────

// P-256 curve order. Used for range checks and low-s classification.
const P256_N =
  0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const P256_HALF_N = P256_N >> 1n;

/** Decode an 0x-prefixed 32-byte hex string to a Buffer. */
function hex32(h: string): Buffer {
  const clean = h.startsWith("0x") ? h.slice(2) : h;
  if (clean.length !== 64) throw new Error(`expected 32-byte hex, got ${clean.length / 2} bytes`);
  return Buffer.from(clean, "hex");
}

interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

program
  .command("verify")
  .description("Run a full sign/verify round-trip against the card and report pass/fail")
  .action(async () => {
    const checks: Check[] = [];
    let passed = 0;

    const record = (ok: boolean, name: string, detail?: string) => {
      checks.push({ ok, name, detail });
      if (ok) passed++;
    };

    try {
      await withReader(async (reader) => {
        // ── 1. Applet selectable + key readable ─────────────────────────────
        // readCardPublicKey() internally SELECTs the applet (AID F07991A3EA7F2C)
        // and sends GET_PUBLIC_KEY (INS 0x01). If the applet isn't installed,
        // the SELECT throws with a non-9000 SW and we capture it as a FAIL.
        let key1: { x: string; y: string };
        try {
          key1 = await readCardPublicKey(reader);
          record(true, "Applet selected (AID F07991A3EA7F2C)");
        } catch (err: any) {
          record(false, "Applet selected (AID F07991A3EA7F2C)", err.message);
          throw err;
        }

        // ── 2. Public key lies on P-256 ─────────────────────────────────────
        // Construct an uncompressed point (0x04 || X || Y) and hand it to
        // @noble/curves. ProjectivePoint.fromHex validates the point equation.
        const pubHex = "04" + key1.x.slice(2) + key1.y.slice(2);
        let pubPoint: ReturnType<typeof p256.ProjectivePoint.fromHex>;
        try {
          pubPoint = p256.ProjectivePoint.fromHex(pubHex);
          pubPoint.assertValidity();
          record(true, "Public key readable (64 bytes, valid P-256 point)");
        } catch (err: any) {
          record(false, "Public key readable (64 bytes, valid P-256 point)", err.message);
          throw err;
        }

        // ── 3. Key stable across two reads ───────────────────────────────────
        const key2 = await readCardPublicKey(reader);
        const stable = key1.x === key2.x && key1.y === key2.y;
        record(stable, "Key stable across two reads", stable ? undefined :
          `first: (${key1.x.slice(0, 10)}…, ${key1.y.slice(0, 10)}…)\n` +
          `second: (${key2.x.slice(0, 10)}…, ${key2.y.slice(0, 10)}…)`);

        // ── 4. Signature produced with r,s in range ─────────────────────────
        const testHash = ethers.id("tool-rental burn test " + Date.now());
        const hash32 = hex32(testHash);

        let sig1: { r: string; s: string };
        try {
          sig1 = await signHash(reader, hash32);
        } catch (err: any) {
          record(false, "Signature produced (64 bytes, r/s in range)", err.message);
          throw err;
        }

        const r1Big = BigInt(sig1.r);
        const s1Big = BigInt(sig1.s);
        const r1InRange = r1Big > 0n && r1Big < P256_N;
        const s1InRange = s1Big > 0n && s1Big < P256_N;
        record(r1InRange && s1InRange,
          "Signature produced (64 bytes, r/s in range)",
          (r1InRange && s1InRange) ? undefined :
            `r in range: ${r1InRange}, s in range: ${s1InRange}`);

        // ── 5. Signature verifies against the card's own public key ─────────
        // The applet uses ALG_ECDSA_SHA_256, which SHA-256-hashes the input
        // before ECDSA. We must verify against sha256(testHash), not testHash.
        // This matches RentalEscrow._verifyStartSignature which does the same.
        const digest = Buffer.from(ethers.sha256(testHash).slice(2), "hex");
        // @noble/curves p256.verify wants the signature as a concatenated
        // 64-byte (r || s) Buffer and the message digest as a Buffer.
        const sigBytes = Buffer.concat([hex32(sig1.r), hex32(sig1.s)]);
        const pubBytes = Buffer.from(pubHex, "hex");
        let verifies = false;
        try {
          verifies = p256.verify(sigBytes, digest, pubBytes);
        } catch {
          verifies = false;
        }
        record(verifies, "Signature verifies (SHA-256 preprocessing matched)",
          verifies ? undefined :
            "The card's signature did not verify against its own public key.\n" +
            "Most likely causes:\n" +
            "  - Card isn't the ToolRental applet (wrong AID / wrong CAP file)\n" +
            "  - SHA-256 preprocessing mismatch between applet and verifier");

        // ── 6. s half classification (informational, non-fatal) ─────────────
        const half = s1Big <= P256_HALF_N ? "lower" : "upper";
        record(true,
          `s is in the ${half} half of the curve (OZ P256.verify needs lower)`);

        // ── 7. Signing is nondeterministic ──────────────────────────────────
        // ECDSA uses a random nonce k, so two signs of the same hash must
        // produce different (r, s) pairs. If they're equal, k is being reused
        // — which would also leak the private key.
        const sig2 = await signHash(reader, hash32);
        const nondeterministic = sig1.r !== sig2.r || sig1.s !== sig2.s;
        record(nondeterministic, "Signing is nondeterministic (two signs → distinct (r, s))",
          nondeterministic ? undefined :
            "Two signs of the same hash returned identical (r, s). This is a\n" +
            "critical failure — it means the card is reusing its random nonce k,\n" +
            "which leaks the private key.");

        // Also verify the second signature independently.
        const sig2Bytes = Buffer.concat([hex32(sig2.r), hex32(sig2.s)]);
        const sig2Verifies = p256.verify(sig2Bytes, digest, pubBytes);
        record(sig2Verifies, "Second signature also verifies");

        // ── 8. NDEF tag applet serves the expected URI record ──────────────
        // The sibling NdefApplet (AID D2760000850101) exposes an NFC Forum
        // Type 4 Tag with one short URI record:
        //     toolrental://card/<xHex><yHex>
        // where (xHex, yHex) is the 64-byte P-256 public key we just read.
        // We walk the Type 4 read chain (SELECT app → SELECT CC → READ CC →
        // SELECT NDEF → READ NDEF) and assert each stage. This catches both
        // the "cold-tap link won't fire on Android" failure mode and the
        // more subtle "key in NDEF URI doesn't match the one the applet
        // signs with" mismatch, which would break the deep-link routing.
        const NDEF_AID = Buffer.from("D2760000850101", "hex");
        const apduSelectNdefApp = Buffer.from([0x00, 0xA4, 0x04, 0x00, NDEF_AID.length, ...NDEF_AID, 0x00]);
        const apduSelectCc      = Buffer.from([0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03]);
        const apduReadCc        = Buffer.from([0x00, 0xB0, 0x00, 0x00, 0x0F]);
        const apduSelectNdef    = Buffer.from([0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04]);
        // Canonical Type 4 NDEF read: first READ_BINARY at offset 0 with Le=2
        // to get NLEN, then READ_BINARY at offset 2 with Le=NLEN for the body.
        // ACR122U firmware misbehaves on `Le=0x00` (up-to-256) when the total
        // NDEF file is large (it's advertised at 330 bytes on our cards) —
        // the PC/SC layer surfaces this as "An error occurred while
        // transmitting". Reading a known length avoids the long-response
        // path entirely.
        const apduReadNlen = Buffer.from([0x00, 0xB0, 0x00, 0x00, 0x02]);
        function buildReadNdefBody(nlen: number): Buffer {
          // Offset 2 past the NLEN prefix. Le is the byte-count to read.
          return Buffer.from([0x00, 0xB0, 0x00, 0x02, nlen & 0xFF]);
        }

        let ndefChainOk = true;
        try {
          parseResponse(await reader.transmit(apduSelectNdefApp, 256));
          record(true, "NDEF applet selectable (AID D2760000850101)");
        } catch (err: any) {
          record(false, "NDEF applet selectable (AID D2760000850101)", err.message);
          ndefChainOk = false;
        }

        if (ndefChainOk) {
          try {
            parseResponse(await reader.transmit(apduSelectCc, 256));
            const ccBytes = parseResponse(await reader.transmit(apduReadCc, 256));
            if (ccBytes.length < 15) {
              throw new Error(`CC file too short: ${ccBytes.length} bytes`);
            }
            // NDEF File Control TLV layout in CC (NFC Forum Type 4 v2.0):
            //   [7]=T(0x04) [8]=L(0x06) [9..10]=FileID [11..12]=MaxSize
            //   [13]=ReadAccess [14]=WriteAccess
            const maxNdefSize = ccBytes.readUInt16BE(11);
            const readAccess  = ccBytes[13];
            if (maxNdefSize === 0) {
              throw new Error("CC advertises max NDEF file size = 0 (file marked empty)");
            }
            if (readAccess !== 0x00) {
              throw new Error(`CC read-access byte is 0x${readAccess.toString(16)} — must be 0x00 (open)`);
            }
            record(true, `CC file sane (max NDEF size ${maxNdefSize} bytes, read-open)`);
          } catch (err: any) {
            record(false, "CC file sane", err.message);
            ndefChainOk = false;
          }
        }

        if (ndefChainOk) {
          try {
            parseResponse(await reader.transmit(apduSelectNdef, 256));
            // Two-step read: first 2 bytes are NLEN, then read exactly NLEN
            // body bytes from offset 2. Avoids the ACR122U long-Le=0 bug.
            const nlenBytes = parseResponse(await reader.transmit(apduReadNlen, 8));
            if (nlenBytes.length < 2) {
              throw new Error(`NLEN read returned ${nlenBytes.length} bytes (expected 2)`);
            }
            const nlen = nlenBytes.readUInt16BE(0);
            if (nlen === 0) {
              throw new Error("NLEN is 0 — NDEF file is empty (init never populated it)");
            }
            if (nlen > 255) {
              // Our cards carry a ~150-byte record; anything beyond 255 means
              // we'd need chained READ_BINARY calls, which we don't implement.
              throw new Error(`NLEN (${nlen}) > 255, chained read not implemented`);
            }
            const bodyBytes = parseResponse(
              await reader.transmit(buildReadNdefBody(nlen), nlen + 8),
            );
            if (bodyBytes.length < nlen) {
              throw new Error(
                `body read returned ${bodyBytes.length} bytes (expected ${nlen})`,
              );
            }
            // Parse the first short URI record from the body. Record 1 is
            // the https URL (abbreviation 0x04 = "https://").
            const rec = bodyBytes.subarray(0, nlen);
            if (rec.length < 5) {
              throw new Error(`record too short: ${rec.length} bytes`);
            }
            const header     = rec[0];
            const typeLen    = rec[1];
            const payloadLen = rec[2];
            if ((header & 0x07) !== 0x01) {
              throw new Error(`unexpected TNF: ${header & 0x07} (want 1 = Well-Known)`);
            }
            if ((header & 0x10) === 0) {
              throw new Error("record not marked SR (short-record) — parser expects SR form");
            }
            if (typeLen !== 1 || rec[3] !== 0x55) {
              throw new Error("record is not an NFC Well-Known URI ('U') record");
            }
            const abbrev = rec[4];
            if (abbrev !== 0x04) {
              throw new Error(`unexpected URI abbreviation byte 0x${abbrev.toString(16)} (want 0x04 = "https://")`);
            }
            const uriEnd = 5 + (payloadLen - 1);
            if (uriEnd > rec.length) {
              throw new Error(`URI length (${payloadLen - 1}) exceeds record body`);
            }
            // Abbreviation 0x04 means the payload omits "https://" — prepend it.
            const uriSuffix = rec.subarray(5, uriEnd).toString("ascii");
            const uri = `https://${uriSuffix}`;
            const cardKeyHash = ethers.sha256(ethers.concat([key1.x, key1.y]));
            const expectedUri = `https://pyrite.rocks/tools/${cardKeyHash.slice(2)}`;
            const match = uri === expectedUri;
            record(match, "NDEF URI record encodes the card's public key",
              match ? undefined :
                `got:      ${uri}\nexpected: ${expectedUri}`);
          } catch (err: any) {
            record(false, "NDEF URI record encodes the card's public key", err.message);
          }
        }

        // ── Summary ─────────────────────────────────────────────────────────
        console.log("\nTool Rental — card verification\n");
        for (const c of checks) {
          const tag = c.ok ? "\x1b[32m[ok]  \x1b[0m" : "\x1b[31m[fail]\x1b[0m";
          console.log(`  ${tag} ${c.name}`);
          if (c.detail) {
            for (const line of c.detail.split("\n")) console.log(`         ${line}`);
          }
        }
        console.log(`\n${passed}/${checks.length} checks passed.`);
        console.log(`\nPublic key X: ${key1.x}`);
        console.log(`Public key Y: ${key1.y}`);
        const hashHex = ethers.sha256(ethers.concat([key1.x, key1.y])).slice(2);
        console.log(`Card key hash: 0x${hashHex}`);

        // Read rentalIdStore
        let rentalId: string | null = null;
        try {
          rentalId = await readRentalId(reader);
          const isZero = rentalId === "0x" + "00".repeat(32);
          console.log(`Rental ID: ${isZero ? "(none)" : rentalId}`);
        } catch {
          console.log(`Rental ID: (unsupported — old applet?)`);
        }

        console.log(`\nNDEF URLs stored on card:`);
        console.log(`  toolrental://card/${hashHex}`);
        console.log(`  https://pyrite.rocks/tools/${hashHex}`);

        if (passed !== checks.length) {
          process.exitCode = 1;
        }
      });
    } catch (err: any) {
      // withReader throws any unhandled error; we've already recorded a
      // failing check above where possible. Print the summary of what we
      // got before exiting.
      if (checks.length > 0) {
        console.log("\nTool Rental — card verification (aborted)\n");
        for (const c of checks) {
          const tag = c.ok ? "\x1b[32m[ok]  \x1b[0m" : "\x1b[31m[fail]\x1b[0m";
          console.log(`  ${tag} ${c.name}`);
          if (c.detail) {
            for (const line of c.detail.split("\n")) console.log(`         ${line}`);
          }
        }
        console.log(`\n${passed}/${checks.length} checks passed before abort.`);
      }
      console.error(`\nVerification aborted: ${err.message}`);
      process.exitCode = 1;
    }
  });

// ── provision command ─────────────────────────────────────────────────────────

program
  .command("provision")
  .description("Mint a ToolNFT for the card, registering the card address on-chain")
  .requiredOption("--owner <address>", "Ethereum address of the tool owner (lender)")
  .option("--rpc-url <url>", "RPC URL", process.env.RPC_URL)
  .option("--toolnft <address>", "ToolNFT contract address", process.env.TOOLNFT_ADDRESS)
  .option("--private-key <key>", "Contract owner's Ethereum private key (for minting)", process.env.PRIVATE_KEY)
  .action(async (opts) => {
    const { owner, rpcUrl, toolnft: toolNftAddress, privateKey } = opts;

    if (!rpcUrl) throw new Error("--rpc-url or RPC_URL env var required");
    if (!toolNftAddress) throw new Error("--toolnft or TOOLNFT_ADDRESS env var required");
    if (!privateKey) throw new Error("--private-key or PRIVATE_KEY env var required");

    if (!ethers.isAddress(owner)) throw new Error(`Invalid owner address: ${owner}`);

    await withReader(async (reader) => {
      console.log(`\nProvisioning new tool NFT for owner: ${owner}`);

      // Step 1: Read card public key
      console.log("\n[1/3] Reading card public key...");
      const { x: cardKeyX, y: cardKeyY } = await readCardPublicKey(reader);
      console.log("  Card key X:", cardKeyX);
      console.log("  Card key Y:", cardKeyY);

      // Step 2: Connect to Ethereum
      console.log("\n[2/3] Connecting to Ethereum...");
      const provider = new ethers.JsonRpcProvider(rpcUrl);
      const wallet = new ethers.Wallet(privateKey, provider);
      const toolNft = new ethers.Contract(toolNftAddress, TOOLNFT_ABI, wallet);

      const network = await provider.getNetwork();
      console.log("  Network:", network.name, `(chainId: ${network.chainId})`);
      console.log("  Signer (contract owner):", wallet.address);

      // Step 3: Mint NFT
      console.log("\n[3/3] Minting ToolNFT on-chain...");
      const tx = await toolNft.mint(owner, cardKeyX, cardKeyY, "");
      console.log("  Tx hash:", tx.hash);
      const receipt = await tx.wait();
      console.log("  Confirmed in block:", receipt.blockNumber);

      // Parse tokenId from Transfer event
      let tokenId: string = "(unknown)";
      const iface = new ethers.Interface(TOOLNFT_ABI);
      for (const log of receipt.logs) {
        try {
          const parsed = iface.parseLog(log);
          if (parsed?.name === "Transfer" && parsed.args.from === ethers.ZeroAddress) {
            tokenId = parsed.args.tokenId.toString();
            break;
          }
        } catch {}
      }

      console.log("\nProvisioning complete!");
      console.log(`  Token ID:  ${tokenId}`);
      console.log(`  Card X:    ${cardKeyX}`);
      console.log(`  Card Y:    ${cardKeyY}`);
      console.log(`  Owner:     ${owner}`);
      console.log(`\nNext step: lender must call toolNft.setApprovalForAll(escrowAddress, true)`);
      console.log(`before listing the tool in the mobile app.`);
    });
  });

// ── NFC helper ────────────────────────────────────────────────────────────────

function withReader(fn: (reader: any) => Promise<void>): Promise<void> {
  return new Promise((resolve, reject) => {
    const nfc = new NFC();
    let handled = false;

    nfc.on("reader", (reader: any) => {
      console.log(`NFC reader detected: ${reader.name}`);
      console.log("Waiting for card...\n");

      // We manage SELECT ourselves via selectApplet() in card.ts, so disable
      // nfc-pcsc's built-in auto-processing (which otherwise throws
      // "Cannot process ISO 14443-4 tag because AID was not set").
      reader.autoProcessing = false;

      reader.on("card", async (card: any) => {
        console.log("Card detected. ATR:", card.atr?.toString("hex") ?? "N/A");
        try {
          await fn(reader);
          handled = true;
          reader.close();
          nfc.close();
          resolve();
        } catch (err) {
          reader.close();
          nfc.close();
          reject(err);
        }
      });

      reader.on("error", (err: Error) => {
        if (!handled) reject(err);
      });
    });

    nfc.on("error", (err: Error) => {
      reject(err);
    });

    setTimeout(() => {
      if (!handled) {
        nfc.close();
        reject(new Error("Timeout: no NFC reader found within 30 seconds"));
      }
    }, 30000);
  });
}

program.parseAsync(process.argv).catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
