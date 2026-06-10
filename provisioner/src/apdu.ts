// SPDX-License-Identifier: MIT
/**
 * APDU command builders for the ToolRental JavaCard applet.
 *
 * AID: F0 79 91 A3 EA 7F 2C (proprietary ISO 7816-5 category 'F'; the old
 * A0000006170001 is rejected by iOS CoreNFC as a "non-permissible identifier").
 */

export const APPLET_AID = Buffer.from("F07991A3EA7F2C", "hex");

export const CLA = 0x00;
export const INS_GET_PUBLIC_KEY = 0x01;
export const INS_SIGN = 0x02;
export const INS_GET_COUNTER = 0x03;
export const INS_GET_RENTAL_ID = 0x04;

/**
 * Build SELECT APDU to activate the applet.
 */
export function buildSelectApdu(): Buffer {
  return Buffer.from([
    0x00, 0xa4, 0x04, 0x00,
    APPLET_AID.length,
    ...APPLET_AID,
    0x00,
  ]);
}

/**
 * Build GET_PUBLIC_KEY APDU.
 * Response: 64 bytes (X || Y, no 0x04 prefix).
 */
export function buildGetPublicKeyApdu(): Buffer {
  return Buffer.from([CLA, INS_GET_PUBLIC_KEY, 0x00, 0x00, 0x40]);
}

/**
 * Build SIGN APDU.
 * @param hash32 32-byte hash to sign. Must commit to the card's next counter
 *               value (read via GET_COUNTER earlier in the same session).
 * @param options.p1 P1 byte: 0x01 = compute & store rentalId (StartRental).
 * @param options.p2 P2 byte: 0x01 = clear rentalIdStore (EndRental).
 * Response: 72 bytes — r[32] || s[32] || counter[8] (counter big-endian).
 */
export function buildSignApdu(hash32: Buffer, options?: { p1?: number; p2?: number }): Buffer {
  if (hash32.length !== 32) throw new Error("Hash must be 32 bytes");
  const p1 = options?.p1 ?? 0x00;
  const p2 = options?.p2 ?? 0x00;
  return Buffer.from([CLA, INS_SIGN, p1, p2, 0x20, ...hash32, 0x48]);
}

/**
 * Build GET_COUNTER APDU.
 * Response: 8 bytes big-endian — the next counter value SIGN will consume.
 */
export function buildGetCounterApdu(): Buffer {
  return Buffer.from([CLA, INS_GET_COUNTER, 0x00, 0x00, 0x08]);
}

/**
 * Build GET_RENTAL_ID APDU.
 * Response: 32 bytes — current rentalIdStore. All zeros = no active rental.
 */
export function buildGetRentalIdApdu(): Buffer {
  return Buffer.from([CLA, INS_GET_RENTAL_ID, 0x00, 0x00, 0x20]);
}

/**
 * Parse response and check SW (status word).
 * Throws if the card returned an error SW.
 */
export function parseResponse(response: Buffer): Buffer {
  const sw = response.readUInt16BE(response.length - 2);
  if (sw !== 0x9000) {
    throw new Error(`Card error: SW=${sw.toString(16).toUpperCase().padStart(4, "0")}`);
  }
  return response.subarray(0, response.length - 2);
}
