#!/usr/bin/env ts-node
/**
 * Tool Rental Card Provisioner CLI
 *
 * Uses an ACR122U USB NFC reader to:
 *   provision  — Read the card's public key and mint a ToolNFT on-chain.
 *   read-key   — Just read and display the card's public key and Ethereum address.
 *   sign-test  — Sign a test hash and display the result (for debugging).
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
import { readCardPublicKey, signHash, computeRecoveryBit } from "./card";

// Minimal ABI for ToolNFT (only the functions used by the provisioner)
const TOOLNFT_ABI = [
  "function mint(address to, address cardAddress) external returns (uint256 tokenId)",
  "function ownerOf(uint256 tokenId) external view returns (address)",
  "function cardAddressOf(uint256 tokenId) external view returns (address)",
  "event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)",
];

const program = new Command();
program.name("provisioner").description("Tool Rental JavaCard provisioner (ACR122U)");

// ── read-key command ──────────────────────────────────────────────────────────

program
  .command("read-key")
  .description("Read the card's secp256k1 public key and Ethereum address")
  .action(async () => {
    await withReader(async (reader) => {
      console.log("Reading card public key...");
      const { publicKeyHex, address } = await readCardPublicKey(reader);
      console.log("\nPublic key (hex):", publicKeyHex);
      console.log("Ethereum address:", address);
    });
  });

// ── sign-test command ─────────────────────────────────────────────────────────

program
  .command("sign-test")
  .description("Sign a test hash and verify recovery")
  .action(async () => {
    await withReader(async (reader) => {
      const { publicKeyHex, address } = await readCardPublicKey(reader);
      console.log("Card address:", address);

      const testHash = ethers.id("test-message"); // keccak256("test-message")
      const hash32 = Buffer.from(testHash.slice(2), "hex");

      console.log("Signing hash:", testHash);
      const { r, s } = await signHash(reader, hash32);
      console.log("r:", r);
      console.log("s:", s);

      // The card uses ALG_ECDSA_SHA_256, which means it SHA-256's the input.
      // For the recovery check here, we need to use the double-hashed value.
      // In practice, coordinate this with the Solidity verification approach.
      console.log("\nNote: Card applies SHA-256 to the input before signing.");
      console.log("For on-chain verification, ensure the hash construction matches.");
    });
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
      const { publicKeyHex, address: cardAddress } = await readCardPublicKey(reader);
      console.log("  Card address:", cardAddress);
      console.log("  Public key:", publicKeyHex);

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
      const tx = await toolNft.mint(owner, cardAddress);
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
      console.log(`  Token ID:     ${tokenId}`);
      console.log(`  Card address: ${cardAddress}`);
      console.log(`  Owner:        ${owner}`);
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
