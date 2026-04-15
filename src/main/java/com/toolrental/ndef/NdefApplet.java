package com.toolrental.ndef;

import com.toolrental.CardKeyShareable;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * NFC Forum Type 4 Tag applet. Emits a three-record NDEF message the phone's
 * OS reader picks up on tap:
 *
 *   1. URI record: toolrental://card/<xHex><yHex>
 *      (custom scheme — uniquely owned by our app, so Android's NDEF dispatch
 *      routes taps straight to us with no browser chooser)
 *   2. URI record: https://pyriteship.xyz/tools/<xHex><yHex>
 *      (stored with URI abbreviation code 0x04 = "https://" to save 8 bytes;
 *      used by phones that don't have the app installed — they fall back to
 *      a browser landing page)
 *   3. Text record: "Tool Rental Card" (en)
 *      (fallback label for Android's system Tag UI and third-party NFC
 *      readers like NFC Tools)
 *
 * Why the custom scheme is first: Android's NFC TagDispatch uses the *first*
 * URI record in the first NDEF message to decide which activity to launch.
 * Putting toolrental:// first guarantees the tap wakes our app with no
 * ambiguity — no reliance on Android App Links verification, no risk of a
 * browser winning the chooser.
 *
 * iPhone trade-off: Core NFC's background reader only surfaces tags whose
 * *first* record is an http/https URI, and ignores custom schemes entirely.
 * So the https URL being record 2 means iPhones show nothing on tap. The
 * path to unlock iPhone support is to host
 * https://pyriteship.xyz/.well-known/assetlinks.json with the app's signing
 * certificate SHA-256 fingerprint, then reorder so the https URL is record 1
 * and flip android:autoVerify="true" on the Android intent filter. At that
 * point Android App Links will route verified taps to the app directly,
 * iPhone will get a Safari notification, and the toolrental:// record can
 * eventually be dropped.
 *
 * (x, y) is the 64-byte P-256 public key of the sibling ToolRentalApplet,
 * rendered as 128 lowercase hex chars concatenated with no separator. The
 * NDEF file is built once at first-select by reading the sibling applet's
 * key via the CardKeyShareable interface and baked into persistent memory.
 * At runtime this applet only answers the four Type 4 commands (SELECT app,
 * SELECT FILE, READ BINARY on CC and NDEF files).
 *
 * Registered AID: D2:76:00:00:85:01:01 — the NFC Forum Type 4 well-known AID
 * that Android's tag dispatch sends SELECT to when polling for NDEF tags.
 *
 * Protocol reference: NFC Forum Type 4 Tag Operation Specification v2.0;
 * NFC Forum URI RTD 1.0 (for the abbreviation code table).
 */
public class NdefApplet extends Applet {

    // ── Constants ─────────────────────────────────────────────────────────────

    /** Sibling applet AID. Must match javacard/pom.xml for ToolRentalApplet. */
    private static final byte[] TOOL_RENTAL_AID = {
        (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x06, (byte)0x17, (byte)0x00, (byte)0x01
    };

    // ISO 7816 instruction bytes we handle
    private static final byte INS_SELECT      = (byte) 0xA4;
    private static final byte INS_READ_BINARY = (byte) 0xB0;

    // File IDs (NFC Forum Type 4)
    private static final short FILE_CC   = (short) 0xE103;
    private static final short FILE_NDEF = (short) 0xE104;

    // Selected-file state
    private static final byte FILE_NONE     = (byte) 0;
    private static final byte FILE_SEL_CC   = (byte) 1;
    private static final byte FILE_SEL_NDEF = (byte) 2;

    // Capability Container (15 bytes, see §5.1 of the Type 4 spec):
    //   00 0F        CCLEN (15)
    //   20           mapping version 2.0
    //   00 FF        MLe  — max R-APDU data size we accept
    //   00 FF        MLc  — max C-APDU data size we accept
    //   04 06 E1 04 XX XX 00 00   NDEF File Control TLV:
    //     T=04 L=06  E104=file ID, XXXX=max NDEF file size, 00=read always, 00=write (unused)
    private static final byte[] CC_FILE_TEMPLATE = {
        (byte)0x00, (byte)0x0F,               // CCLEN
        (byte)0x20,                           // Mapping version 2.0
        (byte)0x00, (byte)0xFF,               // MLe
        (byte)0x00, (byte)0xFF,               // MLc
        (byte)0x04, (byte)0x06,               // NDEF File Control TLV T, L
        (byte)0xE1, (byte)0x04,               // NDEF file ID
        (byte)0x00, (byte)0x00,               // NDEF file max size — patched at install
        (byte)0x00,                           // Read access: always
        (byte)0x00                            // Write access: always (unused)
    };

    // Record 1 — custom-scheme URI payload: 1-byte abbreviation code (0x00 =
    // "no prefix", full URI in body) + "toolrental://card/" + 128 hex chars.
    //
    // Size constants are hard-coded integer literals on purpose: the JavaCard
    // converter rejects arraylength / iadd bytecode in the class initializer,
    // so `URI_PAYLOAD_PREFIX.length` etc. cannot be used in a static-final
    // short's initializer. Keep these in sync if the arrays change.
    private static final byte[] CUSTOM_URI_PREFIX = {
        (byte) 0x00,                                 // URI abbreviation: none
        't','o','o','l','r','e','n','t','a','l',':','/','/','c','a','r','d','/'
    };
    private static final short CUSTOM_URI_PREFIX_LEN = (short) 19;   // = CUSTOM_URI_PREFIX.length
    private static final short HEX_KEY_LEN           = (short) 128;  // 64 bytes → 128 hex
    private static final short CUSTOM_URI_PAYLOAD_LEN = (short) 147; // 19 + 128

    // Record 2 — https URI payload: 1-byte abbreviation code (0x04 = "https://")
    // + "pyriteship.xyz/tools/" + 128 hex chars.
    private static final byte[] HTTPS_URI_PREFIX = {
        (byte) 0x04,                                 // URI abbreviation: "https://"
        'p','y','r','i','t','e','s','h','i','p','.','x','y','z','/','t','o','o','l','s','/'
    };
    private static final short HTTPS_URI_PREFIX_LEN = (short) 22;    // = HTTPS_URI_PREFIX.length
    private static final short HTTPS_URI_PAYLOAD_LEN = (short) 150;  // 22 + 128

    // Record 3 — Text payload: status byte + ISO 639-1 language code + UTF-8.
    // Status byte 0x02 = UTF-8 encoding, 2-byte language code.
    private static final byte[] LABEL_TEXT = {
        'T','o','o','l',' ','R','e','n','t','a','l',' ','C','a','r','d'
    };
    private static final short LABEL_TEXT_LEN   = (short) 16;   // = LABEL_TEXT.length
    private static final short TEXT_PAYLOAD_LEN = (short) 19;   // 1 (status) + 2 (lang) + 16 (text)

    // NDEF file layout:
    //   [0..1] NLEN — big-endian length of NDEF message (not including NLEN)
    //   [2..]  NDEF message bytes (record 1 || record 2 || record 3)
    //
    // All records are Well-Known TNF (001), short form (SR=1), no ID field.
    //
    // Record 1 — URI, first record, not last:
    //   header=0x91 type_len=0x01 pay_len=CUSTOM_URI_PAYLOAD_LEN type='U'
    //   payload=[0x00 || "toolrental://card/" || hex key]
    //
    // Record 2 — URI, middle record:
    //   header=0x11 type_len=0x01 pay_len=HTTPS_URI_PAYLOAD_LEN type='U'
    //   payload=[0x04 || "pyriteship.xyz/tools/" || hex key]
    //
    // Record 3 — Text, last record:
    //   header=0x51 type_len=0x01 pay_len=TEXT_PAYLOAD_LEN type='T'
    //   payload=[0x02 || 'e' 'n' || LABEL_TEXT]
    private static final short CUSTOM_URI_RECORD_LEN = (short) 151;  // 4 + 147
    private static final short HTTPS_URI_RECORD_LEN  = (short) 154;  // 4 + 150
    private static final short TEXT_RECORD_LEN       = (short) 23;   // 4 + 19
    private static final short NDEF_RECORD_LEN       = (short) 328;  // 151 + 154 + 23
    private static final short NDEF_FILE_LEN         = (short) 330;  // 2 + 328

    // ── Persistent state ──────────────────────────────────────────────────────

    private byte[] ccFile;     // 15 bytes
    private byte[] ndefFile;   // NDEF_FILE_LEN bytes
    private byte[] keyBuf;     // persistent 64-byte buffer for the Shareable read
    private byte currentFile;
    private boolean initialized;

    // ── Installation ──────────────────────────────────────────────────────────

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // Install-time keeps it simple: allocate buffers and register. The
        // cross-applet Shareable lookup happens lazily on the first SELECT,
        // because doing it at install time triggered 6F00 on the J3R180 —
        // the sibling's install has completed but the link/loader state is
        // still in flux when two applets from different packages are being
        // brought up back-to-back. By the first real SELECT the card has
        // been through a reset and everything is settled.
        NdefApplet applet = new NdefApplet();
        applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    private NdefApplet() {
        currentFile = FILE_NONE;
        initialized = false;

        // Build the CC file from the template, patching in the NDEF file
        // max-size field. In the NDEF File Control TLV the layout is:
        //   [7]=T(0x04) [8]=L(0x06) [9..10]=FileID [11..12]=MaxSize
        //   [13]=ReadAccess [14]=WriteAccess
        // so the max-size bytes live at [11,12] — NOT [12,13].
        ccFile = new byte[(short) CC_FILE_TEMPLATE.length];
        Util.arrayCopyNonAtomic(CC_FILE_TEMPLATE, (short) 0,
                                ccFile, (short) 0, (short) CC_FILE_TEMPLATE.length);
        ccFile[11] = (byte) ((NDEF_FILE_LEN >> 8) & 0xFF);
        ccFile[12] = (byte) (NDEF_FILE_LEN & 0xFF);

        // Allocate the NDEF file and the key read buffer as persistent arrays.
        // keyBuf is 64 bytes — the Shareable impl writes X||Y into the APDU
        // buffer (a JCRE global entry-point array) and we copy it out into
        // keyBuf here. See NdefApplet.initializeFromSibling.
        ndefFile = new byte[NDEF_FILE_LEN];
        keyBuf = new byte[(short) 64];
    }

    /**
     * One-shot lazy initialisation: reach into the sibling ToolRentalApplet
     * via the Shareable interface, pull its public key, and bake the NDEF
     * URI record into this.ndefFile. Called from the first SELECT — by then
     * the card has been reset once since install, and both packages are
     * fully linked.
     */
    private void initializeFromSibling() {
        AID toolRentalAid = JCSystem.lookupAID(TOOL_RENTAL_AID, (short) 0,
                                               (byte) TOOL_RENTAL_AID.length);
        if (toolRentalAid == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        CardKeyShareable sharable = (CardKeyShareable)
            JCSystem.getAppletShareableInterfaceObject(toolRentalAid, (byte) 0);
        if (sharable == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Have the sibling drop the 64 raw key bytes into the APDU buffer.
        // We must fetch the APDU buffer reference in OUR context and hand
        // it over as a parameter — APDU.getCurrentAPDUBuffer() throws
        // SecurityException from the server's context (it's not the
        // currently-selected applet during the cross-context call).
        //
        // The APDU buffer is a JCRE global array, so passing it as a
        // Shareable method argument bypasses the firewall (which would
        // otherwise reject any caller-owned byte[] parameter).
        //
        // Copy immediately out into keyBuf — the JCRE does not preserve
        // the APDU buffer across dispatches.
        byte[] apduBuf = APDU.getCurrentAPDUBuffer();
        sharable.writePublicKey(apduBuf, (short) 0);
        Util.arrayCopyNonAtomic(apduBuf, (short) 0, keyBuf, (short) 0, (short) 64);

        // Construct the NDEF file: NLEN prefix + three records
        // (custom URI, https URI, Text).
        short off = 0;
        ndefFile[off++] = (byte) ((NDEF_RECORD_LEN >> 8) & 0xFF);
        ndefFile[off++] = (byte) (NDEF_RECORD_LEN & 0xFF);

        // Record 1: custom-scheme URI. MB=1, ME=0, SR=1, TNF=WKT → 0x91.
        ndefFile[off++] = (byte) 0x91;
        ndefFile[off++] = (byte) 0x01;                 // type length
        ndefFile[off++] = (byte) CUSTOM_URI_PAYLOAD_LEN;
        ndefFile[off++] = (byte) 0x55;                 // type 'U'
        Util.arrayCopyNonAtomic(CUSTOM_URI_PREFIX, (short) 0,
                                ndefFile, off, CUSTOM_URI_PREFIX_LEN);
        off += CUSTOM_URI_PREFIX_LEN;
        off = writeHex(keyBuf, (short) 0, (short) 64, ndefFile, off);

        // Record 2: https URI. MB=0, ME=0, SR=1, TNF=WKT → 0x11.
        ndefFile[off++] = (byte) 0x11;
        ndefFile[off++] = (byte) 0x01;                 // type length
        ndefFile[off++] = (byte) HTTPS_URI_PAYLOAD_LEN;
        ndefFile[off++] = (byte) 0x55;                 // type 'U'
        Util.arrayCopyNonAtomic(HTTPS_URI_PREFIX, (short) 0,
                                ndefFile, off, HTTPS_URI_PREFIX_LEN);
        off += HTTPS_URI_PREFIX_LEN;
        off = writeHex(keyBuf, (short) 0, (short) 64, ndefFile, off);

        // Record 3: Text. MB=0, ME=1, SR=1, TNF=WKT → 0x51.
        ndefFile[off++] = (byte) 0x51;
        ndefFile[off++] = (byte) 0x01;                 // type length
        ndefFile[off++] = (byte) TEXT_PAYLOAD_LEN;
        ndefFile[off++] = (byte) 0x54;                 // type 'T'
        ndefFile[off++] = (byte) 0x02;                 // status: UTF-8, 2-byte lang
        ndefFile[off++] = (byte) 'e';
        ndefFile[off++] = (byte) 'n';
        Util.arrayCopyNonAtomic(LABEL_TEXT, (short) 0,
                                ndefFile, off, LABEL_TEXT_LEN);
        off += LABEL_TEXT_LEN;

        initialized = true;
    }

    /**
     * Write `len` bytes from src[srcOff..] as 2 lowercase hex chars each into
     * dest[destOff..]. Returns the new destOff after writing.
     */
    private static short writeHex(byte[] src, short srcOff, short len,
                                  byte[] dest, short destOff) {
        final byte[] HEX = {
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f'
        };
        for (short i = 0; i < len; i++) {
            byte b = src[(short)(srcOff + i)];
            dest[destOff++] = HEX[(b >> 4) & 0x0F];
            dest[destOff++] = HEX[b & 0x0F];
        }
        return destOff;
    }

    // ── APDU dispatch ─────────────────────────────────────────────────────────

    public void process(APDU apdu) {
        if (selectingApplet()) {
            // First-select initialisation — populate the NDEF file from the
            // sibling applet's public key. Runs once per card lifetime.
            if (!initialized) {
                initializeFromSibling();
            }
            currentFile = FILE_NONE;
            return;
        }

        byte[] buf = apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_SELECT:
                handleSelectFile(apdu);
                break;
            case INS_READ_BINARY:
                handleReadBinary(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * SELECT FILE by file ID — P1=0x00, P2=0x0C (first or only, no FCI), Lc=2,
     * data = 2-byte file ID (big-endian).
     */
    private void handleSelectFile(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        if (p1 != (byte) 0x00 || p2 != (byte) 0x0C) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short lc = apdu.setIncomingAndReceive();
        if (lc != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short fileId = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        if (fileId == FILE_CC) {
            currentFile = FILE_SEL_CC;
        } else if (fileId == FILE_NDEF) {
            currentFile = FILE_SEL_NDEF;
        } else {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    }

    /**
     * READ BINARY — P1/P2 = 16-bit offset, Le = requested length. Returns
     * bytes from whichever file was last selected.
     */
    private void handleReadBinary(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short offset = Util.makeShort(buf[ISO7816.OFFSET_P1], buf[ISO7816.OFFSET_P2]);
        short le = apdu.setOutgoing();

        byte[] file;
        short fileLen;
        if (currentFile == FILE_SEL_CC) {
            file = ccFile;
            fileLen = (short) ccFile.length;
        } else if (currentFile == FILE_SEL_NDEF) {
            file = ndefFile;
            fileLen = (short) ndefFile.length;
        } else {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            return;
        }

        if (offset > fileLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short available = (short) (fileLen - offset);
        // ISO 7816-4 short-form Le=0x00 means "up to 256 bytes". Some PC/SC
        // stacks (notably ACR122U) only size the response buffer for 256 and
        // error out mid-transmit if the card sends more — so when the host
        // asks for 0, we must cap at 256, not return the full remaining file.
        // For explicit Le values we still trim to what's actually available.
        if (le == 0) {
            le = available > 256 ? (short) 256 : available;
        } else if (le > available) {
            le = available;
        }

        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(file, offset, le);
    }
}
