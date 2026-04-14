package com.toolrental;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Tool Rental NFC JavaCard Applet for J3R180 (JCOP4-180K).
 *
 * This applet generates a P-256 (secp256r1) key pair on first installation and
 * provides two APDU commands:
 *
 *   INS 0x01  GET_PUBLIC_KEY  — Returns the 64-byte uncompressed public key (X || Y).
 *   INS 0x02  SIGN            — Accepts a 32-byte hash and returns a 64-byte raw
 *                               ECDSA signature (r || s).
 *
 * The private key is generated on-card and never exported. The card's P-256
 * public key coordinates (X, Y) are registered on-chain in ToolNFT.sol.
 *
 * P-256 (secp256r1 / NIST P-256) is a named curve natively supported by the
 * J3R180 hardware crypto accelerator, so no external library is required.
 *
 * AID: A0 00 00 06 17 00 01 (7 bytes, registered private range)
 *
 * P-256 curve parameters:
 *   p  = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
 *   a  = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
 *   b  = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
 *   Gx = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
 *   Gy = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
 *   n  = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 *   h  = 1
 */
public class ToolRentalApplet extends Applet implements CardKeyShareable {

    // ── APDU instruction bytes ────────────────────────────────────────────────
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x01;
    private static final byte INS_SIGN           = (byte) 0x02;

    // ── P-256 (secp256r1) curve parameters ──────────────────────────────��────
    private static final byte[] P256_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF
    };
    private static final byte[] P256_A = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFC
    };
    private static final byte[] P256_B = {
        (byte)0x5A,(byte)0xC6,(byte)0x35,(byte)0xD8,(byte)0xAA,(byte)0x3A,(byte)0x93,(byte)0xE7,
        (byte)0xB3,(byte)0xEB,(byte)0xBD,(byte)0x55,(byte)0x76,(byte)0x98,(byte)0x86,(byte)0xBC,
        (byte)0x65,(byte)0x1D,(byte)0x06,(byte)0xB0,(byte)0xCC,(byte)0x53,(byte)0xB0,(byte)0xF6,
        (byte)0x3B,(byte)0xCE,(byte)0x3C,(byte)0x3E,(byte)0x27,(byte)0xD2,(byte)0x60,(byte)0x4B
    };
    private static final byte[] P256_G = {
        (byte)0x04, // uncompressed point prefix
        (byte)0x6B,(byte)0x17,(byte)0xD1,(byte)0xF2,(byte)0xE1,(byte)0x2C,(byte)0x42,(byte)0x47,
        (byte)0xF8,(byte)0xBC,(byte)0xE6,(byte)0xE5,(byte)0x63,(byte)0xA4,(byte)0x40,(byte)0xF2,
        (byte)0x77,(byte)0x03,(byte)0x7D,(byte)0x81,(byte)0x2D,(byte)0xEB,(byte)0x33,(byte)0xA0,
        (byte)0xF4,(byte)0xA1,(byte)0x39,(byte)0x45,(byte)0xD8,(byte)0x98,(byte)0xC2,(byte)0x96,
        (byte)0x4F,(byte)0xE3,(byte)0x42,(byte)0xE2,(byte)0xFE,(byte)0x1A,(byte)0x7F,(byte)0x9B,
        (byte)0x8E,(byte)0xE7,(byte)0xEB,(byte)0x4A,(byte)0x7C,(byte)0x0F,(byte)0x9E,(byte)0x16,
        (byte)0x2B,(byte)0xCE,(byte)0x33,(byte)0x57,(byte)0x6B,(byte)0x31,(byte)0x5E,(byte)0xCE,
        (byte)0xCB,(byte)0xB6,(byte)0x40,(byte)0x68,(byte)0x37,(byte)0xBF,(byte)0x51,(byte)0xF5
    };
    private static final byte[] P256_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xBC,(byte)0xE6,(byte)0xFA,(byte)0xAD,(byte)0xA7,(byte)0x17,(byte)0x9E,(byte)0x84,
        (byte)0xF3,(byte)0xB9,(byte)0xCA,(byte)0xC2,(byte)0xFC,(byte)0x63,(byte)0x25,(byte)0x51
    };

    // ── Key storage (persistent) ──────────────────────────────────────────────
    private ECPrivateKey  privateKey;
    private ECPublicKey   publicKey;
    private Signature     signer;

    // ── Transient scratch buffer ────────────────────────────────��─────────────
    // Holds the 64-byte raw signature output (r || s) before copying to APDU.
    // Also used as scratch for public key export (65 bytes with prefix byte).
    private byte[] scratch;
    private static final short SCRATCH_SIZE = (short) 80;

    // ── Installation ───────────────────────────���──────────────────────────────

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ToolRentalApplet().register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    private ToolRentalApplet() {
        scratch = JCSystem.makeTransientByteArray(SCRATCH_SIZE, JCSystem.CLEAR_ON_DESELECT);
        generateKeyPair();

        // ECDSA signer using SHA-256 (card hashes the input before signing)
        signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    }

    /**
     * Generate a P-256 key pair on-card. Called once at install time.
     * The private key never leaves the card.
     */
    private void generateKeyPair() {
        privateKey = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        publicKey = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);

        setP256Params(privateKey);
        setP256Params(publicKey);

        KeyPair kp = new KeyPair(publicKey, privateKey);
        kp.genKeyPair();
    }

    private void setP256Params(ECKey key) {
        key.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
        key.setA(P256_A, (short) 0, (short) P256_A.length);
        key.setB(P256_B, (short) 0, (short) P256_B.length);
        key.setG(P256_G, (short) 0, (short) P256_G.length);
        key.setR(P256_N, (short) 0, (short) P256_N.length);
        key.setK((short) 1);
    }

    // ── APDU dispatch ─────────────────────────────────────────────────────────

    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) return;

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_GET_PUBLIC_KEY:
                handleGetPublicKey(apdu);
                break;
            case INS_SIGN:
                handleSign(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * INS 0x01 GET_PUBLIC_KEY
     *
     * Command:  CLA=00 INS=01 P1=00 P2=00 Le=40
     * Response: 64 bytes — uncompressed public key (X[32] || Y[32]), no prefix byte.
     *
     * The caller stores X and Y as two bytes32 values on-chain in ToolNFT.sol.
     */
    private void handleGetPublicKey(APDU apdu) {
        // Export uncompressed point: 0x04 || X || Y = 65 bytes
        short pubLen = publicKey.getW(scratch, (short) 0);
        // pubLen should be 65. Skip the 0x04 prefix byte, return 64 bytes.
        if (pubLen != 65 || scratch[0] != (byte) 0x04) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 64);
        apdu.sendBytesLong(scratch, (short) 1, (short) 64);
    }

    /**
     * INS 0x02 SIGN
     *
     * Command:  CLA=00 INS=02 P1=00 P2=00 Lc=20 [32-byte hash] Le=40
     * Response: 64 bytes — DER-decoded raw signature (r[32] || s[32]).
     *
     * The 32-byte hash sent by the mobile app is the keccak256 commitment:
     *   keccak256(abi.encode(toolId|rentalId, phase, challenge, chainId, contractAddress))
     *
     * Note: ALG_ECDSA_SHA_256 will SHA-256 the input before signing. The caller
     * must account for this: send the raw 32-byte hash and the card will sign
     * SHA256(hash). Both sides must use the same pre-image consistently.
     */
    private void handleSign(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (dataLen != 32) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        signer.init(privateKey, Signature.MODE_SIGN);

        // DER-encoded ECDSA signature can be up to 72 bytes.
        // Store in scratch, then decode to raw r||s.
        short sigLen = signer.sign(buf, ISO7816.OFFSET_CDATA, (short) 32, scratch, (short) 0);

        // Decode DER signature to raw (r || s): each is 32 bytes big-endian.
        short outLen = derToRaw(scratch, sigLen);
        if (outLen != 64) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 64);
        apdu.sendBytesLong(scratch, (short) 0, (short) 64);
    }

    /**
     * Decode a DER-encoded ECDSA signature into raw r||s in-place at scratch[0..63].
     * DER format: 30 [total-len] 02 [r-len] [r-bytes] 02 [s-len] [s-bytes]
     * Raw format: r[32] || s[32], zero-padded on the left.
     *
     * Returns 64 on success, 0 on error.
     */
    private short derToRaw(byte[] der, short derLen) {
        // Minimal DER sanity check
        if (der[0] != 0x30) return 0;
        short off = 2; // skip 0x30 and length byte

        // Extract r
        if (der[off] != 0x02) return 0;
        off++;
        short rLen = (short)(der[off] & 0xFF);
        off++;
        short rStart = off;
        off += rLen;

        // Extract s
        if (der[off] != 0x02) return 0;
        off++;
        short sLen = (short)(der[off] & 0xFF);
        off++;
        short sStart = off;

        // Write r into scratch[0..31], right-aligned, zero-padded
        byte[] out = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
        short rCopy = rLen > 32 ? (short)32 : rLen;
        short rSrcOff = (short)(rStart + (rLen > 32 ? (short)(rLen - 32) : 0));
        short rDstOff = (short)(32 - rCopy);
        Util.arrayCopyNonAtomic(der, rSrcOff, out, rDstOff, rCopy);

        // Write s into out[32..63], right-aligned, zero-padded
        short sCopy = sLen > 32 ? (short)32 : sLen;
        short sSrcOff = (short)(sStart + (sLen > 32 ? (short)(sLen - 32) : 0));
        short sDstOff = (short)(64 - sCopy);
        Util.arrayCopyNonAtomic(der, sSrcOff, out, sDstOff, sCopy);

        Util.arrayCopyNonAtomic(out, (short)0, scratch, (short)0, (short)64);
        return 64;
    }

    // ── CardKeyShareable ──────────────────────────────────────────────────────

    /**
     * Write the raw 64-byte public key (X || Y) into `globalBuf` at
     * `offset`. Called cross-context via CardKeyShareable from NdefApplet.
     *
     * `globalBuf` MUST be a JCRE global array — the caller passes in the
     * APDU buffer reference it fetched from its own context. We cannot
     * fetch it ourselves: APDU.getCurrentAPDUBuffer() throws
     * SecurityException from a non-selected context. We also cannot touch
     * our own CLEAR_ON_DESELECT transient `scratch` here (same reason —
     * we're not the selected applet during this call) or accept a
     * caller-owned regular array (firewall rejects).
     *
     * getW writes the 65-byte 0x04-prefixed uncompressed form; we shift
     * X||Y left by one to overwrite the leading 0x04.
     */
    public void writePublicKey(byte[] globalBuf, short offset) {
        short pubLen = publicKey.getW(globalBuf, offset);
        if (pubLen != 65 || globalBuf[offset] != (byte) 0x04) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Util.arrayCopyNonAtomic(globalBuf, (short)(offset + 1), globalBuf, offset, (short) 64);
    }

    /**
     * JavaCard calls this when a sibling applet requests a Shareable. We only
     * hand out the key-export interface; parameter is ignored for now.
     */
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        return this;
    }
}
