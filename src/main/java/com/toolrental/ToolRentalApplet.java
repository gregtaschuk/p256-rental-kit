package com.toolrental;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
import opencrypto.jcmathlib.*;

/**
 * Tool Rental NFC JavaCard Applet for J3R180 (JCOP4-180K).
 *
 * This applet generates a secp256k1 key pair on first installation and provides
 * two APDU commands:
 *
 *   INS 0x01  GET_PUBLIC_KEY  — Returns the 64-byte uncompressed public key (X || Y).
 *   INS 0x02  SIGN            — Accepts a 32-byte hash and returns a 64-byte raw
 *                               ECDSA signature (r || s).
 *
 * The private key is generated on-card and never exported. The card's Ethereum
 * address is derived off-card from the public key:
 *   address = rightmost 20 bytes of keccak256(publicKey)
 *
 * AID: A0 00 00 06 17 00 01 (7 bytes, registered private range)
 *
 * secp256k1 curve parameters (Ethereum / Bitcoin curve):
 *   p  = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 *   a  = 0
 *   b  = 7
 *   Gx = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
 *   Gy = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
 *   n  = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 *   h  = 1
 */
public class ToolRentalApplet extends Applet {

    // ── APDU instruction bytes ────────────────────────────────────────────────
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x01;
    private static final byte INS_SIGN           = (byte) 0x02;

    // ── secp256k1 curve parameters ────────────────────────────────────────────
    private static final byte[] SECP256K1_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };
    private static final byte[] SECP256K1_A = { 0x00 };
    private static final byte[] SECP256K1_B = { 0x07 };
    private static final byte[] SECP256K1_G = {
        (byte)0x04, // uncompressed point prefix
        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
    };
    private static final byte[] SECP256K1_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };

    // ── Key storage (persistent) ──────────────────────────────────────────────
    private ECPrivateKey  privateKey;
    private ECPublicKey   publicKey;
    private Signature     signer;

    // ── Transient scratch buffer ──────────────────────────────────────────────
    // Holds the 64-byte raw signature output (r || s) before copying to APDU.
    // Also used as scratch for public key export (65 bytes with prefix byte).
    private byte[] scratch;
    private static final short SCRATCH_SIZE = (short) 80;

    // ── Installation ──────────────────────────────────────────────────────────

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ToolRentalApplet().register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    private ToolRentalApplet() {
        scratch = JCSystem.makeTransientByteArray(SCRATCH_SIZE, JCSystem.CLEAR_ON_DESELECT);
        generateKeyPair();

        // ECDSA signer using SHA-256 (card hashes the input before signing)
        // We pass pre-hashed 32-byte input, so we use ALG_ECDSA_SHA (SHA-1) or
        // a raw/external hash variant. JCOP4 supports ALG_ECDSA_SHA_256.
        signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    }

    /**
     * Generate a secp256k1 key pair on-card. Called once at install time.
     * The private key never leaves the card.
     */
    private void generateKeyPair() {
        privateKey = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        publicKey = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);

        setSecp256k1Params(privateKey);
        setSecp256k1Params(publicKey);

        KeyPair kp = new KeyPair(publicKey, privateKey);
        kp.genKeyPair();
    }

    private void setSecp256k1Params(ECKey key) {
        key.setFieldFP(SECP256K1_P, (short) 0, (short) SECP256K1_P.length);
        key.setA(SECP256K1_A, (short) 0, (short) SECP256K1_A.length);
        key.setB(SECP256K1_B, (short) 0, (short) SECP256K1_B.length);
        key.setG(SECP256K1_G, (short) 0, (short) SECP256K1_G.length);
        key.setR(SECP256K1_N, (short) 0, (short) SECP256K1_N.length);
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
     * The caller derives the Ethereum address as:
     *   address = keccak256(pubKey)[12:]
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
     * Alternatively, use a raw ECDSA variant if available on the specific card.
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
}
