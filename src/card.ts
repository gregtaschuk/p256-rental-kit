/**
 * High-level card operations using the ACR122U via nfc-pcsc.
 */

import { buildSelectApdu, buildGetPublicKeyApdu, buildSignApdu, parseResponse } from "./apdu";

export interface CardReader {
  transmit(data: Buffer, responseMaxLength: number): Promise<Buffer>;
}

/**
 * Select the ToolRental applet on the card.
 */
export async function selectApplet(reader: CardReader): Promise<void> {
  const apdu = buildSelectApdu();
  const response = await reader.transmit(apdu, 256);
  parseResponse(response); // throws on non-9000
  console.log("  Applet selected successfully.");
}

/**
 * Read the card's P-256 public key.
 * Returns { x, y } as 0x-prefixed 32-byte hex strings.
 */
export async function readCardPublicKey(reader: CardReader): Promise<{ x: string; y: string }> {
  await selectApplet(reader);

  const apdu = buildGetPublicKeyApdu();
  const response = await reader.transmit(apdu, 68); // 64 bytes + 2 SW bytes
  const pubKeyBytes = parseResponse(response); // 64 bytes: X || Y

  if (pubKeyBytes.length !== 64) {
    throw new Error(`Unexpected public key length: ${pubKeyBytes.length}`);
  }

  return {
    x: "0x" + pubKeyBytes.subarray(0, 32).toString("hex"),
    y: "0x" + pubKeyBytes.subarray(32, 64).toString("hex"),
  };
}

/**
 * Ask the card to sign a 32-byte hash.
 * Returns { r, s } as hex strings (32 bytes each).
 *
 * Note: The card runs SHA-256 on the input before signing (ALG_ECDSA_SHA_256).
 * Ensure the signing format on the Solidity side matches.
 */
export async function signHash(reader: CardReader, hash32: Buffer): Promise<{ r: string; s: string }> {
  await selectApplet(reader);

  if (hash32.length !== 32) throw new Error("hash32 must be exactly 32 bytes");

  const apdu = buildSignApdu(hash32);
  const response = await reader.transmit(apdu, 68); // 64 bytes + 2 SW
  const sigBytes = parseResponse(response); // 64 bytes: r || s

  if (sigBytes.length !== 64) {
    throw new Error(`Unexpected signature length: ${sigBytes.length}`);
  }

  return {
    r: "0x" + sigBytes.subarray(0, 32).toString("hex"),
    s: "0x" + sigBytes.subarray(32, 64).toString("hex"),
  };
}

