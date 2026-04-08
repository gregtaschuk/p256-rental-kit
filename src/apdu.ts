/**
 * APDU command builders for the ToolRental JavaCard applet.
 *
 * AID: A0 00 00 06 17 00 01
 */

export const APPLET_AID = Buffer.from("A0000006170001", "hex");

export const CLA = 0x00;
export const INS_GET_PUBLIC_KEY = 0x01;
export const INS_SIGN = 0x02;

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
 * @param hash32 32-byte hash to sign.
 * Response: 64 bytes (r || s).
 */
export function buildSignApdu(hash32: Buffer): Buffer {
  if (hash32.length !== 32) throw new Error("Hash must be 32 bytes");
  return Buffer.from([CLA, INS_SIGN, 0x00, 0x00, 0x20, ...hash32, 0x40]);
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
