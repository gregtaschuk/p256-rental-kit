/**
 * High-level card operations using the ACR122U via nfc-pcsc.
 */

import {
  buildSelectApdu,
  buildGetPublicKeyApdu,
  buildSignApdu,
  buildGetCounterApdu,
  parseResponse,
} from "./apdu";

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
 * Read the card's next counter value without consuming it.
 * Response is an 8-byte big-endian unsigned integer.
 */
export async function readCardCounter(reader: CardReader): Promise<bigint> {
  await selectApplet(reader);
  const apdu = buildGetCounterApdu();
  const response = await reader.transmit(apdu, 12); // 8 bytes + 2 SW
  const bytes = parseResponse(response);
  if (bytes.length !== 8) {
    throw new Error(`Unexpected counter length: ${bytes.length}`);
  }
  return BigInt("0x" + bytes.toString("hex"));
}

/**
 * Ask the card to sign a 32-byte hash. Returns (r, s) plus the counter value
 * the card just consumed.
 *
 * Note: The card runs SHA-256 on the input before signing (ALG_ECDSA_SHA_256).
 * The 32-byte hash MUST already commit to the same counter value the card is
 * about to consume (fetched via `readCardCounter` earlier in the same session),
 * otherwise on-chain verification will reject the signature.
 */
export async function signHash(
  reader: CardReader,
  hash32: Buffer,
): Promise<{ r: string; s: string; counter: bigint }> {
  await selectApplet(reader);

  if (hash32.length !== 32) throw new Error("hash32 must be exactly 32 bytes");

  const apdu = buildSignApdu(hash32);
  const response = await reader.transmit(apdu, 76); // 72 bytes + 2 SW
  const sigBytes = parseResponse(response);

  if (sigBytes.length !== 72) {
    throw new Error(`Unexpected signature length: ${sigBytes.length}`);
  }

  return {
    r: "0x" + sigBytes.subarray(0, 32).toString("hex"),
    s: "0x" + sigBytes.subarray(32, 64).toString("hex"),
    counter: BigInt("0x" + sigBytes.subarray(64, 72).toString("hex")),
  };
}

