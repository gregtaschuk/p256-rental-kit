package com.toolrental;

import javacard.framework.Shareable;

/**
 * Shareable interface exposing the ToolRentalApplet's 64-byte raw P-256
 * public key (X || Y, without the 0x04 uncompressed prefix) to sibling
 * applets in the same CAP via JCSystem.getAppletShareableInterfaceObject().
 *
 * Currently used by NdefApplet at install time to build the static NDEF
 * URI record that identifies this card.
 */
public interface CardKeyShareable extends Shareable {
    /**
     * Write the raw 64-byte public key (X[32] || Y[32]) into `globalBuf`
     * starting at `offset`.
     *
     * Cross-context data exchange rules on JC 3.0.5:
     *   1. The firewall does NOT grant cross-context access to array
     *      parameters passed to a Shareable method — writing into a
     *      caller-owned byte[] from the server context throws
     *      SecurityException (surfacing as SW 6F00).
     *   2. Global arrays (like the APDU buffer) ARE accessible from every
     *      context and CAN legally be passed as Shareable parameters.
     *   3. The server cannot call APDU.getCurrentAPDUBuffer() itself —
     *      that throws SecurityException unless the active context owns
     *      the currently-selected applet, which it does not during a
     *      cross-context Shareable invocation.
     *
     * Putting (1)–(3) together: the caller must fetch the APDU buffer
     * reference in its own context and hand it in as `globalBuf`. Any
     * non-global array will trip the firewall.
     *
     * The caller copies the 64 bytes out into private storage immediately
     * after the call returns — the APDU buffer is not preserved between
     * APDU dispatches.
     */
    void writePublicKey(byte[] globalBuf, short offset);
}
